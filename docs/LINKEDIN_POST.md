# LinkedIn Launch Draft

I built **SentinelOps AI**, a human-governed incident-response platform for Kubernetes on AWS.

Instead of connecting an LLM directly to production, I designed a bounded control plane. SentinelOps correlates an alert with read-only Kubernetes and Prometheus evidence through MCP tools, retrieves versioned runbooks, and uses Amazon Bedrock to return a structured diagnosis with citations and confidence. A deterministic policy engine rejects invented evidence and unsafe actions. Any remediation proposal requires a short-lived approval tied to the incident, action, and approver, and every step is recorded in a tamper-evident audit chain.

The platform is deployed with Terraform, EKS, Helm, Argo CD, GitHub Actions OIDC, Prometheus/Grafana, and OpenTelemetry-ready instrumentation. I also built golden incident evaluations that gate model and prompt changes on citation accuracy, safe escalation, and unsafe-action rejection.

The most important lesson: senior AI platform engineering is less about adding a chatbot and more about identity, evidence, evaluation, failure modes, auditability, and controlled authority.

#AWS #AmazonBedrock #Kubernetes #EKS #Terraform #DevOps #SRE #MCP #GenerativeAI #PlatformEngineering #DevSecOps
