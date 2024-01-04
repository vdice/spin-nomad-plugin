use anyhow::Context;
use reqwest::Client;

pub struct NomadClient {
    http_client: Client,
    base_url: String,
}

impl NomadClient {
    pub fn new(base_url: &String) -> Self {
        let http_client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        Self {
            http_client,
            base_url: base_url.to_string(),
        }
    }

    pub async fn parse_job(&self, hcl: &str) -> Result<String, anyhow::Error> {
        let url = format!("{}/v1/jobs/parse", self.base_url);
        let job_hcl = JobHCL {
            hcl: hcl.to_string(),
            canonicalize: true,
        };
        let resp = self
            .http_client
            .post(&url)
            .json(&job_hcl)
            .send()
            .await
            .context("failed to parse job hcl")?;

        Ok(resp.text().await?)
    }

    pub async fn post_job(&self, job: String) -> Result<(), anyhow::Error> {
        let url = format!("{}/v1/jobs", self.base_url);
        let job_spec = JobSpec {
            job: serde_json::from_str::<serde_json::Value>(&job).unwrap(),
        };
        self.http_client
            .post(&url)
            .json(&job_spec)
            .send()
            .await
            .context("failed to post job")?;

        Ok(())
    }
}

#[derive(serde::Serialize)]
pub struct JobHCL {
    #[serde(rename(serialize = "JobHCL"))]
    pub hcl: String,
    #[serde(rename(serialize = "Canonicalize"))]
    pub canonicalize: bool,
}

#[derive(serde::Serialize)]
pub struct JobSpec {
    #[serde(rename(serialize = "Job"))]
    pub job: serde_json::Value,
}
