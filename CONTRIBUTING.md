# Contributing

SentinelOps AI is a portfolio reference implementation, but issues and pull requests are welcome.

## Development checks

Use Python 3.12 and run:

```bash
python -m pip install -e '.[dev]'
ruff check .
pytest --cov=sentinelops --cov-fail-under=80
python scripts/validate_project.py
python scripts/evaluate.py
terraform fmt -check -recursive infrastructure/terraform
helm lint platform/chart --set image.repository=example.invalid/sentinelops --set image.tag=test
```

## Pull requests

- Explain the operational problem and the proposed control.
- Include tests for policy, approval, retrieval, or execution changes.
- Preserve the rule that the LLM and MCP diagnostic tools have no direct mutation authority.
- Update the changelog for user-visible behavior.
- Never commit credentials, approval secrets, cloud account identifiers, or unredacted incident data.

## Security reports

Do not open a public issue for a suspected vulnerability. Follow [SECURITY.md](SECURITY.md).
