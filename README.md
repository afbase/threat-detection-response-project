# Threat Detection and Response Project

The goal for this project is to learn how to build an abuse detection system end to end, split into two services, and develop the necessary threat detection and incident response measures for it.

1. **Technical Design Document**: You'll draft a technical design document detailing the Login Web App, the Abuse Detection API, the observability stack, and the trust boundary between the two.  
2. **Python Services**: Build the Login Web App and the Abuse Detection API in Python  
3. **Observability**: Setup Prometheus, Fluentd, Loki, Alertmanager, and Grafana via Docker Compose  
4. **Detection and Response**: We’ll conduct several threat detection and response scenarios once the components are all put together

## Technical Design Document

Give a high level problem statement, high level solution, what is in scope (and what's not), and an architecture diagram of solution. Cover why the system is split into two services (login web app and abuse detection api) and where the trust boundary between them sits, proxy, and observability stack.

## Login Web App

With Python and FastAPI, you'll create the user-facing Login Web App. It should possess the following:

1. GET /login: Login page  
2. POST /login: passes the username and password, then calls the Abuse Detection API to decide allow, step-up, or deny  
3. GET /success: If /login succeeds, 302 to this page

The Login Web App sits behind huginn-proxy and forwards the TLS fingerprint headers it receives to the Abuse Detection API on each call.

## Abuse Detection API

With Python and FastAPI, you'll create an internal, stateless Abuse Detection API service. It should possess the following:

1. POST /v1/loginCheck: Takes in a json containing (username, IP, user agent, timestamp, success or fail) and returns "allow", "step-up", or "deny" with a reason. Develop criteria for each.  
2. POST /v2/loginCheck: same as v1 but also handles TLS [JA4 Fingerprinting](https://blog.foxio.io/ja4+-network-fingerprinting) from the proxy. You are to develop criteria for "allow", "step-up", or "deny" with a reason.

This API should only trust fingerprint headers that come from the proxy, and should reject or ignore them from any other caller.

### TLS JA4 Fingerprinting

You'll use the [huginn-proxy](https://github.com/biandratti/huginn-proxy) to get the details of the TLS Fingerprint. The proxy passes the details as [headers](https://biandratti.github.io/huginn-proxy/docs/fingerprinting/).

## Observability

Alongside both services will be a suite of observability tools. You'll need to add logs, metrics, and spans to both the Login Web App and the Abuse Detection API.

- Once your observability is setup, we should be able to have a dashboard in grafana that:  
1. Gives histogram of ciphersuites in TLS Fingerprints  
2. Gives the median times of spans for GET and POST login routes  
3. Histogram of allow, step-up, deny over time  
4. Correlates a Login Web App trace to the Abuse Detection API decision that produced it  
- One should be able to search logs in grafana  
- One should be able to develop alerts in grafana

## Detection and Response

Once the Login app, Abuse Detection API, proxy, and observability stack is setup, we can run some scenarios around threat detection and response.

1. **Credential stuffing:** Many usernames, few passwords, all from a scripted client sharing the same JA4 fingerprint. Should be caught via the ciphersuite histogram (one fingerprint dominating) and the failed-login rate.  
2. **Low-and-slow password spray:** Many usernames, one or two common passwords each, spread out to stay under a naive rate-limit alert. Tests whether alert thresholds account for volume over a longer window, not just spikes.  
3. **Fingerprint evasion:** After early denies, the attacker rotates or spoofs JA4 fingerprints to look like different legitimate browsers while reusing the same IP or username pattern. Tests detection by IP/behavior when fingerprint-based detection is defeated.

For each of the scenarios, we’ll run an incident response for each and go through a kaizen exercise.  