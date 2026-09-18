apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: sentinelops
  namespace: argocd
spec:
  project: default
  source:
    repoURL: ${GITOPS_REPO_URL}
    targetRevision: main
    path: platform/chart
    helm:
      parameters:
        - name: image.repository
          value: ${IMAGE_REPOSITORY}
        - name: image.tag
          value: ${IMAGE_TAG}
        - name: bedrock.region
          value: ${AWS_REGION}
        - name: bedrock.modelId
          value: ${BEDROCK_MODEL_ID}
  destination:
    server: https://kubernetes.default.svc
    namespace: sentinelops
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
