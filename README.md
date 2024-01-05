# Spin Nomad Plugin

> Disclaimer: The code here is currently hashed together from the pre-existing [Fermyon Cloud Plugin](https://github.com/fermyon/cloud-plugin), with some code removed, commented-out, updated and added to. It's definitely in need of being cleaned up, but it ~~does~~ ~~should~~ may work and can be considered PoC/demo-ware for the time being.

A [Spin plugin](https://github.com/fermyon/spin-plugins) to deploy apps to [Nomad](https://www.nomadproject.io/) from the [Spin CLI](https://github.com/fermyon/spin).

Currently, it is assumed [Consul](https://www.consul.io/) is also running alongside Nomad.

## Installing the latest plugin

```sh
spin plugin install --url https://github.com/vdice/spin-nomad-plugin/releases/download/canary/nomad.json
```

## Building and installing local changes

1. Install `spin pluginify`

    ```sh
    spin plugins update
    spin plugins install pluginify --yes
    ```

2. Build, package and install the plugin.

    ```sh
    cargo build --release
    spin pluginify --install
    ```

3. Run the plugin.

    ```sh
    spin nomad --help
    ```

## Deploy to Nomad

If you're running Nomad via the local [Fermyon Platform project](https://github.com/fermyon/installer/local) -- and, as of writing, are on
[a branch that runs a local registry service co-located on Nomad](https://github.com/vdice/fermyon-installer/tree/wip/installer-lite) --
then deployment of an app from your local workstation can be done like so:

```sh
spin nomad deploy
```

If you're already using a separate, publicly available OCI registry (eg DockerHub, GHCR, etc) for publishing your app, you would
first publish and then deploy using the published reference:

```sh
spin registry push vdice/hello:0.1.0
spin nomad deploy --from-registry vdice/hello:0.1.0
```

A different Nomad address can be supplied like so:

```sh
spin nomad deploy --nomad-addr http://my.nomad.cluster:4646
```

(Or via the `NOMAD_ADDR` env var)

> Note: Not yet tested; Have only used a local Nomad cluster thus far.

## TODOs

- Explore defaulting to the `nomad` service provider and removing the Consul dependency
- Nomad TLS
- Spin app features: kv stores? sqlite dbs?
- Add login/connection handling to OCI registries
- Refactor CI (use spin-pluginify to package/release, rm .plugin-manifests)