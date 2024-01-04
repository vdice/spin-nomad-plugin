use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::Parser;
use handlebars::Handlebars;
use include_dir::{include_dir, Dir};
use oci_distribution::Reference;
use spin_http::{app_info::AppInfo, routes::RoutePattern};
use spin_locked_app::locked;
use tracing::instrument;

use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
};
use url::Url;

use crate::{
    nomad::NomadClient,
    opts::*,
};

static TEMPLATES_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/src/templates");

const SPIN_DEFAULT_KV_STORE: &str = "default";

/// Deploy a Spin application to Nomad.
#[derive(Parser, Debug)]
#[clap(about = "Deploy a Spin application to Nomad")]
pub struct DeployCommand {
    /// The Nomad address
    #[clap(
        name = NOMAD_ADDR,
        env = "NOMAD_ADDR",
        short = 'n',
        long = "--nomad-addr",
        default_value = DEFAULT_NOMAD_ADDR
    )]
    pub nomad_addr: String,

    /// The application to deploy. This may be a manifest (spin.toml) file, a
    /// directory containing a spin.toml file, or a remote registry reference.
    /// If omitted, it defaults to "spin.toml".
    #[clap(
        name = APPLICATION_OPT,
        short = 'f',
        long = "from",
        group = "source",
    )]
    pub app_source: Option<String>,

    /// The application to deploy. This is the same as `--from` but forces the
    /// application to be interpreted as a file or directory path.
    #[clap(
        hide = true,
        name = APP_MANIFEST_FILE_OPT,
        long = "from-file",
        alias = "file",
        group = "source",
    )]
    pub file_source: Option<PathBuf>,

    /// The application to deploy. This is the same as `--from` but forces the
    /// application to be interpreted as an OCI registry reference.
    #[clap(
        hide = true,
        name = FROM_REGISTRY_OPT,
        long = "from-registry",
        group = "source",
    )]
    pub registry_source: Option<String>,

    /// Ignore registry certificate errors.
    #[clap(
        name = INSECURE_OPT,
        short = 'k',
        long = "insecure",
        takes_value = false,
    )]
    pub insecure: bool,

    /// For local apps, specifies to perform `spin build` before deploying the application.
    ///
    /// This is ignored on remote applications, as they are already built.
    #[clap(long, takes_value = false, env = "SPIN_ALWAYS_BUILD")]
    pub build: bool,

    /// How long in seconds to wait for a deployed HTTP application to become
    /// ready. The default is 60 seconds. Set it to 0 to skip waiting
    /// for readiness.
    #[clap(long = "readiness-timeout", default_value = "60")]
    pub readiness_timeout_secs: u16,
    // TODO: support some/all:
    //
    // /// Set a key/value pair (key=value) in the deployed application's
    // /// default store. Any existing value will be overwritten.
    // /// Can be used multiple times.
    // #[clap(long = "key-value", parse(try_from_str = parse_kv))]
    // pub key_values: Vec<(String, String)>,

    // /// Set a variable (variable=value) in the deployed application.
    // /// Any existing value will be overwritten.
    // /// Can be used multiple times.
    // #[clap(long = "variable", parse(try_from_str = parse_kv))]
    // pub variables: Vec<(String, String)>,
}

impl DeployCommand {
    pub async fn run(self) -> Result<()> {
        if self.build {
            self.run_spin_build().await?;
        }

        self.deploy().await
    }

    fn resolve_app_source(&self) -> AppSource {
        match (&self.app_source, &self.file_source, &self.registry_source) {
            (None, None, None) => self.default_manifest_or_none(),
            (Some(source), None, None) => Self::infer_source(source),
            (None, Some(file), None) => Self::infer_file_source(file.to_owned()),
            (None, None, Some(reference)) => AppSource::OciRegistry(reference.to_owned()),
            _ => AppSource::unresolvable("More than one application source was specified"),
        }
    }

    fn default_manifest_or_none(&self) -> AppSource {
        let default_manifest = PathBuf::from(DEFAULT_MANIFEST_FILE);
        if default_manifest.exists() {
            AppSource::File(default_manifest)
        } else {
            AppSource::None
        }
    }

    fn infer_source(source: &str) -> AppSource {
        let path = PathBuf::from(source);
        if path.exists() {
            Self::infer_file_source(path)
        } else if spin_oci::is_probably_oci_reference(source) {
            AppSource::OciRegistry(source.to_owned())
        } else {
            AppSource::Unresolvable(format!("File or directory '{source}' not found. If you meant to load from a registry, use the `--from-registry` option."))
        }
    }

    fn infer_file_source(path: impl Into<PathBuf>) -> AppSource {
        match spin_common::paths::resolve_manifest_file_path(path.into()) {
            Ok(file) => AppSource::File(file),
            Err(e) => AppSource::Unresolvable(e.to_string()),
        }
    }

    async fn deploy(self) -> Result<()> {
        let dir = tempfile::tempdir()?;

        let application = self.load_app(dir.path()).await?;

        validate_app(&application)?;

        let name = sanitize_app_name(application.name()?);
        let version = sanitize_app_version(application.version()?);
        let reference: String;

        // Publish to registry, maybe
        match self.resolve_app_source() {
            // Reference provided; don't publish to configured registry
            AppSource::OciRegistry(r) => {
                reference = r
            },
            _ => {
                // TODO: variableize
                let registry_host = format!("registry.local.fermyon.link");
                reference = format!(
                    "{}/{}:{}",
                    registry_host,
                    &sanitize_app_name(application.name()?),
                    &sanitize_app_version(application.version()?)
                );
                let oci_ref = Reference::try_from(reference.as_ref())
                    .context(format!("Could not parse reference '{reference}'"))?;
                // TODO: use return value (digest) for oci_reference value in template and wait_for_ready
                let _digest = self.push_oci(application.clone(), oci_ref).await?;
            }
        };

        println!("Deploying to Nomad...");

        let nomad_client = NomadClient::new(&self.nomad_addr);

        let mut handlebars = Handlebars::new();
        let app_job_template = TEMPLATES_DIR
            .get_file("app.nomad.hbs")
            .unwrap()
            .contents_utf8()
            .unwrap();
        handlebars
            .register_template_string("job", app_job_template)
            .unwrap();
        let mut data: HashMap<&str, &str> = HashMap::new();
        data.insert("job_name", &name);
        data.insert("oci_reference", &reference);
        if self.insecure {
            data.insert("insecure", "-k");
        }
        let job_hcl_text = handlebars.render("job", &data).unwrap();

        let job_def = nomad_client.parse_job(job_hcl_text.as_str()).await?;
        nomad_client.post_job(job_def).await?;

        // TODO: variablize this, scheme as well
        let app_domain = "local.fermyon.link";
        let app_base = format!("http://{name}.{app_domain}");
        let app_base_url = url::Url::parse(&app_base)
            .context(format!("unable to parse app base url {app_base}"))?;
        let (http_base, http_routes) = application.http_routes();

        // TODO: use digest once spin adds it to metadata on 'spin up'
        wait_for_ready(
            &app_base_url,
            &version,
            self.readiness_timeout_secs,
            Destination::Nomad(self.nomad_addr),
        )
        .await;
        let base = http_base.unwrap_or_else(|| "/".to_owned());
        print_available_routes(&app_base_url, &base, &http_routes);

        Ok(())
    }

    async fn load_app(&self, working_dir: &Path) -> Result<DeployableApp, anyhow::Error> {
        let app_source = self.resolve_app_source();

        let locked_app = match &app_source {
            AppSource::File(app_file) => {
                spin_loader::from_file(
                    &app_file,
                    spin_loader::FilesMountStrategy::Copy(working_dir.to_owned()),
                )
                .await?
            }
            AppSource::OciRegistry(reference) => {
                let mut oci_client = spin_oci::Client::new(self.insecure, None)
                    .await
                    .context("cannot create registry client")?;

                spin_oci::OciLoader::new(working_dir)
                    .load_app(&mut oci_client, reference)
                    .await?
            }
            AppSource::None => {
                anyhow::bail!("Default file '{DEFAULT_MANIFEST_FILE}' not found.");
            }
            AppSource::Unresolvable(err) => {
                anyhow::bail!("{err}");
            }
        };

        let unsupported_triggers = locked_app
            .triggers
            .iter()
            .filter(|t| t.trigger_type != "http")
            .map(|t| format!("'{}'", t.trigger_type))
            .collect::<Vec<_>>();
        if !unsupported_triggers.is_empty() {
            bail!(
                "Non-HTTP triggers are not supported - app uses {}",
                unsupported_triggers.join(", ")
            );
        }

        Ok(DeployableApp(locked_app))
    }

    async fn push_oci(
        &self,
        application: DeployableApp,
        reference: Reference,
    ) -> Result<Option<String>> {
        let mut client = spin_oci::Client::new(self.insecure, None).await?;

        println!(
            "Publishing {} version {} to registry {}...",
            &reference.repository(),
            &reference.tag().unwrap_or(application.version()?),
            &reference.registry()
        );
        let digest = client
            .push_locked(application.0, reference.to_string())
            .await?;

        Ok(digest)
    }

    async fn run_spin_build(&self) -> Result<()> {
        self.resolve_app_source().build().await
    }
}

// TODO: begin copy/paste from fermyon/cloud-plugin. Look into code re-use?

#[derive(Debug, PartialEq, Eq)]
enum AppSource {
    None,
    File(PathBuf),
    OciRegistry(String),
    Unresolvable(String),
}

fn bin_path() -> anyhow::Result<PathBuf> {
    let bin_path = std::env::var("SPIN_BIN_PATH")?;
    Ok(PathBuf::from(bin_path))
}

impl AppSource {
    fn unresolvable(message: impl Into<String>) -> Self {
        Self::Unresolvable(message.into())
    }

    async fn build(&self) -> anyhow::Result<()> {
        match self {
            Self::File(manifest_path) => {
                let spin_bin = bin_path()?;

                let result = tokio::process::Command::new(spin_bin)
                    .args(["build", "-f"])
                    .arg(manifest_path)
                    .status()
                    .await
                    .context("Failed to execute `spin build` command")?;

                if result.success() {
                    Ok(())
                } else {
                    Err(anyhow!("Build failed: deployment cancelled"))
                }
            }
            _ => Ok(()),
        }
    }
}

// SAFE_APP_NAME regex to only allow letters/numbers/underscores/dashes
lazy_static::lazy_static! {
    static ref SAFE_APP_NAME: regex::Regex = regex::Regex::new("^[-_\\p{L}\\p{N}]+$").expect("Invalid name regex");
}

// TODO: logic here inherited from bindle restrictions; it would be friendlier to users
// to be less stringent and do the necessary sanitization on the backend, rather than
// presenting this error at deploy time.
fn check_safe_app_name(name: &str) -> Result<()> {
    if SAFE_APP_NAME.is_match(name) {
        Ok(())
    } else {
        Err(anyhow!("App name '{}' contains characters that are not allowed. It may contain only letters, numbers, dashes and underscores", name))
    }
}

// Sanitize app name to conform to Docker repo name conventions
// From https://docs.docker.com/engine/reference/commandline/tag/#extended-description:
// The path consists of slash-separated components. Each component may contain lowercase letters, digits and separators.
// A separator is defined as a period, one or two underscores, or one or more hyphens. A component may not start or end with a separator.
fn sanitize_app_name(name: &str) -> String {
    name.to_ascii_lowercase()
        .replace(' ', "")
        .trim_start_matches(|c: char| c == '.' || c == '_' || c == '-')
        .trim_end_matches(|c: char| c == '.' || c == '_' || c == '-')
        .to_string()
}

// Sanitize app version to conform to Docker tag conventions
// From https://docs.docker.com/engine/reference/commandline/tag
// A tag name must be valid ASCII and may contain lowercase and uppercase letters, digits, underscores, periods and hyphens.
// A tag name may not start with a period or a hyphen and may contain a maximum of 128 characters.
fn sanitize_app_version(tag: &str) -> String {
    let mut sanitized = tag
        .trim()
        .trim_start_matches(|c: char| c == '.' || c == '-');

    if sanitized.len() > 128 {
        (sanitized, _) = sanitized.split_at(128);
    }
    sanitized.replace(' ', "")
}

fn validate_app(app: &DeployableApp) -> Result<()> {
    check_safe_app_name(app.name()?)?;
    ensure!(!app.components().is_empty(), "No components in spin.toml!");
    for component in app.components() {
        if let Some(invalid_store) = component
            .key_value_stores()
            .iter()
            .find(|store| *store != SPIN_DEFAULT_KV_STORE)
        {
            bail!("Invalid store {invalid_store:?} for component {:?}. Cloud currently supports only the 'default' store.", component.id());
        }
    }
    Ok(())
}

#[derive(Clone)]
struct DeployableApp(locked::LockedApp);

struct DeployableComponent(locked::LockedComponent);

impl DeployableApp {
    fn name(&self) -> anyhow::Result<&str> {
        self.0
            .metadata
            .get("name")
            .ok_or(anyhow!("Application has no name"))?
            .as_str()
            .ok_or(anyhow!("Application name is not a string"))
    }

    fn version(&self) -> anyhow::Result<&str> {
        self.0
            .metadata
            .get("version")
            .ok_or(anyhow!("Application has no version"))?
            .as_str()
            .ok_or(anyhow!("Application version is not a string"))
    }

    fn components(&self) -> Vec<DeployableComponent> {
        self.0
            .components
            .iter()
            .map(|c| DeployableComponent(c.clone()))
            .collect()
    }

    fn http_routes(&self) -> (Option<String>, Vec<HttpRoute>) {
        let base = self
            .0
            .metadata
            .get("trigger")
            .and_then(|v| v.get("base"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_owned());
        let routes = self
            .0
            .triggers
            .iter()
            .filter_map(|t| self.http_route(t))
            .collect();
        (base, routes)
    }

    fn http_route(&self, trigger: &locked::LockedTrigger) -> Option<HttpRoute> {
        if &trigger.trigger_type != "http" {
            return None;
        }

        let Some(id) = trigger
            .trigger_config
            .get("component")
            .and_then(|v| v.as_str())
        else {
            return None;
        };

        let description = self.component_description(id).map(|s| s.to_owned());
        let route = trigger.trigger_config.get("route").and_then(|v| v.as_str());
        route.map(|r| HttpRoute {
            id: id.to_owned(),
            description,
            route_pattern: r.to_owned(),
        })
    }

    fn component_description(&self, id: &str) -> Option<&str> {
        self.0
            .components
            .iter()
            .find(|c| c.id == id)
            .and_then(|c| c.metadata.get("description").and_then(|v| v.as_str()))
    }
}

#[derive(Debug)]
struct HttpRoute {
    id: String,
    description: Option<String>,
    route_pattern: String,
}

impl DeployableComponent {
    fn id(&self) -> &str {
        &self.0.id
    }

    fn key_value_stores(&self) -> Vec<String> {
        self.metadata_vec_string("key_value_stores")
    }

    fn metadata_vec_string(&self, key: &str) -> Vec<String> {
        let Some(raw) = self.0.metadata.get(key) else {
            return vec![];
        };
        let Some(arr) = raw.as_array() else {
            return vec![];
        };
        arr.iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.to_owned())
            .collect()
    }
}

const READINESS_POLL_INTERVAL_SECS: u64 = 2;

enum Destination {
    Nomad(String),
}

async fn wait_for_ready(
    app_base_url: &Url,
    app_version: &str,
    readiness_timeout_secs: u16,
    destination: Destination,
) {
    if readiness_timeout_secs == 0 {
        return;
    }

    let app_info_url = app_base_url
        .join(spin_http::WELL_KNOWN_PREFIX.trim_start_matches('/'))
        .unwrap()
        .join("info")
        .unwrap()
        .to_string();

    let start = std::time::Instant::now();
    let readiness_timeout = std::time::Duration::from_secs(u64::from(readiness_timeout_secs));
    let poll_interval = tokio::time::Duration::from_secs(READINESS_POLL_INTERVAL_SECS);

    print!("Waiting for application to become ready");
    let _ = std::io::stdout().flush();
    loop {
        match is_ready(&app_info_url, app_version).await {
            Err(err) => {
                println!("... readiness check failed: {err:?}");
                return;
            }
            Ok(true) => {
                println!("... ready");
                return;
            }
            Ok(false) => {}
        }

        print!(".");
        let _ = std::io::stdout().flush();

        if start.elapsed() >= readiness_timeout {
            println!();
            println!("Application deployed, but Spin could not establish readiness");
            match destination {
                Destination::Nomad(url) => {
                    println!("Check the Nomad dashboard to see the application status: {url}");
                }
            }
            return;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

#[instrument(level = "debug")]
async fn is_ready(app_info_url: &str, expected_version: &str) -> Result<bool> {
    // If the request fails, we assume the app isn't ready
    let resp = match reqwest::get(app_info_url).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::warn!("Readiness check failed: {err:?}");
            return Ok(false);
        }
    };
    // If the response status isn't success, the app isn't ready
    if !resp.status().is_success() {
        tracing::debug!("App not ready: {}", resp.status());
        return Ok(false);
    }
    // If the app was previously deployed then it will have an outdated
    // version, in which case the app isn't ready
    if let Ok(app_info) = resp.json::<AppInfo>().await {
        // TODO: use oci_image_digest once spin adds it on `spin up`
        let active_version = app_info.version;
        if active_version.as_deref() != Some(expected_version) {
            tracing::debug!("Active version {active_version:?} != expected {expected_version:?}");
            return Ok(false);
        }
    }
    Ok(true)
}

fn print_available_routes(app_base_url: &Url, base: &str, routes: &[HttpRoute]) {
    // Strip any trailing slash from base URL
    let app_base_url = app_base_url.to_string();
    let route_prefix = app_base_url.strip_suffix('/').unwrap_or(&app_base_url);

    // Ensure base starts with a /
    let base = if !base.starts_with('/') {
        format!("/{base}")
    } else {
        base.to_owned()
    };

    let app_root_url = format!("{route_prefix}{base}");

    println!();
    println!("View application:   {app_root_url}");

    if routes.iter().any(|r| r.route_pattern != "/...") {
        println!("  Routes:");
        for component in routes {
            let route = RoutePattern::from(&base, &component.route_pattern);
            println!("  - {}: {}{}", component.id, route_prefix, route);
            if let Some(description) = &component.description {
                println!("    {}", description);
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accepts_only_valid_app_names() {
        check_safe_app_name("hello").expect("should have accepted 'hello'");
        check_safe_app_name("hello-world").expect("should have accepted 'hello-world'");
        check_safe_app_name("hell0_w0rld").expect("should have accepted 'hell0_w0rld'");

        let _ =
            check_safe_app_name("hello/world").expect_err("should not have accepted 'hello/world'");

        let _ =
            check_safe_app_name("hello world").expect_err("should not have accepted 'hello world'");
    }

    #[test]
    fn should_sanitize_app_name() {
        assert_eq!("hello-world", sanitize_app_name("hello-world"));
        assert_eq!("hello-world2000", sanitize_app_name("Hello-World2000"));
        assert_eq!("hello-world", sanitize_app_name(".-_hello-world_-"));
        assert_eq!("hello-world", sanitize_app_name(" hello -world "));
    }

    #[test]
    fn should_sanitize_app_version() {
        assert_eq!("v0.1.0", sanitize_app_version("v0.1.0"));
        assert_eq!("_v0.1.0", sanitize_app_version("_v0.1.0"));
        assert_eq!("v0.1.0_-", sanitize_app_version(".-v0.1.0_-"));
        assert_eq!("v0.1.0", sanitize_app_version(" v 0.1.0 "));
        assert_eq!(
            "v0.1.0+Hello-World",
            sanitize_app_version(" v 0.1.0+Hello-World ")
        );
        assert_eq!(
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sanitize_app_version("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855e3b")
        );
    }

    fn deploy_cmd_for_test_file(filename: &str) -> DeployCommand {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("testdata")
            .join(filename);
        DeployCommand {
            app_source: None,
            file_source: Some(path),
            registry_source: None,
            build: false,
            readiness_timeout_secs: 60,
            nomad_addr: "localhost:4646".to_string(),
            insecure: false,
            // key_values: vec![],
            // variables: vec![],
        }
    }

    fn get_trigger_base(mut app: DeployableApp) -> String {
        let serde_json::map::Entry::Occupied(trigger) = app.0.metadata.entry("trigger") else {
            panic!("Expected trigger metadata but entry was vacant");
        };
        let base = trigger
            .get()
            .as_object()
            .unwrap()
            .get("base")
            .expect("Manifest should have had a base but didn't");
        base.as_str()
            .expect("HTTP base should have been a string but wasn't")
            .to_owned()
    }

    #[tokio::test]
    async fn if_http_base_is_set_then_it_is_respected() {
        let temp_dir = tempfile::tempdir().unwrap();

        let cmd = deploy_cmd_for_test_file("based_v1.toml");
        let app = cmd.load_app(temp_dir.path()).await.unwrap();
        let base = get_trigger_base(app);
        assert_eq!("/base", base);

        let cmd = deploy_cmd_for_test_file("based_v2.toml");
        let app = cmd.load_app(temp_dir.path()).await.unwrap();
        let base = get_trigger_base(app);
        assert_eq!("/base", base);
    }

    #[tokio::test]
    async fn if_http_base_is_not_set_then_it_is_inserted() {
        let temp_dir = tempfile::tempdir().unwrap();

        let cmd = deploy_cmd_for_test_file("unbased_v1.toml");
        let app = cmd.load_app(temp_dir.path()).await.unwrap();
        let base = get_trigger_base(app);
        assert_eq!("/", base);

        let cmd = deploy_cmd_for_test_file("unbased_v2.toml");
        let app = cmd.load_app(temp_dir.path()).await.unwrap();
        let base = get_trigger_base(app);
        assert_eq!("/", base);
    }

    #[tokio::test]
    async fn plugin_version_should_be_set() {
        let temp_dir = tempfile::tempdir().unwrap();

        let cmd = deploy_cmd_for_test_file("minimal_v2.toml");
        let app = cmd.load_app(temp_dir.path()).await.unwrap();
        let version = app.0.metadata.get("cloud_plugin_version").unwrap();
        assert_eq!(crate::VERSION, version);
    }

    fn string_set(strs: &[&str]) -> HashSet<String> {
        strs.iter().map(|s| s.to_string()).collect()
    }
}
