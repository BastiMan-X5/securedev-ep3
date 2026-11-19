"""
Puerta de seguridad de OWASP ZAP para el pipeline.
Resume el reporte JSON de ZAP y falla si hay alertas de riesgo ALTO,
excepto las que fueron analizadas y documentadas como FALSOS POSITIVOS.
"""
import json
import sys

# Falsos positivos analizados (pluginid de ZAP -> justificacion)
FALSOS_POSITIVOS = {
    "43": (
        "Source Code Disclosure - File Inclusion: ZAP compara la respuesta de "
        "name=<nombre de archivo> con la de name=<valor aleatorio>. Como la app "
        "valida la entrada con lista blanca, responde 200 a uno y 400 al otro, y ZAP "
        "interpreta esa diferencia como inclusion de archivos. La app no lee archivos "
        "del disco: la alerta aparece justamente porque la validacion funciona."
    ),
}

RIESGO = {"3": "ALTO", "2": "MEDIO", "1": "BAJO", "0": "INFORMATIVO"}

with open(sys.argv[1], encoding="utf-8") as f:
    data = json.load(f)

alertas = [a for site in data.get("site", []) for a in site.get("alerts", [])]
alertas.sort(key=lambda a: -int(a.get("riskcode", 0)))

reales = [a for a in alertas if a.get("pluginid") not in FALSOS_POSITIVOS]
fps = [a for a in alertas if a.get("pluginid") in FALSOS_POSITIVOS]
altas_reales = [a for a in reales if a.get("riskcode") == "3"]

if "--exit-code" in sys.argv:
    print(1 if altas_reales else 0)
    sys.exit(0)

print("===== RESUMEN OWASP ZAP =====")
for r in ["ALTO", "MEDIO", "BAJO", "INFORMATIVO"]:
    n = sum(1 for a in reales if RIESGO.get(a.get("riskcode")) == r)
    print(f"  {r:<12}: {n}")
print("")
for a in reales:
    print(f"[{RIESGO.get(a.get('riskcode'), '?')}] {a.get('name')}  (CWE-{a.get('cweid')}, instancias: {a.get('count')})")

if fps:
    print("")
    print("===== FALSOS POSITIVOS ANALIZADOS (no bloquean) =====")
    for a in fps:
        print(f"[{RIESGO.get(a.get('riskcode'), '?')}] {a.get('name')} (plugin {a.get('pluginid')})")
        print(f"    Justificacion: {FALSOS_POSITIVOS[a.get('pluginid')]}")

print("")
print("RESULTADO:", "FALLA - hay alertas reales de riesgo ALTO" if altas_reales
      else "OK - sin alertas reales de riesgo ALTO")
