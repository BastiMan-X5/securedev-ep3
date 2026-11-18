# SecureDev - EP3 Ciberseguridad en Desarrollo (OCY1102)

App Flask usada para el pipeline CI/CD DevSecOps con Jenkins y Docker.

| Etapa del pipeline | Herramienta | Qué revisa |
|---|---|---|
| 1. Checkout y trazabilidad | Git + sha256sum | Commit, autor, fecha y hash de los archivos |
| 2. SAST | Bandit | Malas prácticas de seguridad en Python |
| 3. SAST | Semgrep (reglas en `semgrep-rules.yml`) | XSS, debug activado, secretos en el código |
| 4. Dependencias | pip-audit + Dependabot | CVE conocidas en `requirements.txt` |
| 5. Construcción | Docker | Imagen de la app |
| 6. Despliegue | Docker | Contenedor `securedev-app` en el puerto 5000 |
| 7. DAST | OWASP ZAP | Ataques reales contra la app desplegada |

Monitoreo de producción: Prometheus + Grafana (endpoint `/metrics`).
