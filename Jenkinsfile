// ============================================================================
//  SecureDev - Pipeline CI/CD DevSecOps  (OCY1102 - Evaluacion Parcial 3)
//  Etapas: Trazabilidad -> SAST -> Dependencias -> Construccion -> Despliegue -> DAST (ZAP)
//  Cada etapa de seguridad deja su reporte en reports/ y en la carpeta evidencias/ del PC
// ============================================================================
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '30'))
    }

    // Revisa GitHub cada 2 minutos: cada commit (incluidos los de Dependabot) dispara el pipeline
    triggers {
        pollSCM('H/2 * * * *')
    }

    environment {
        APP_NAME   = 'securedev-app'
        IMAGE      = "securedev-app:${env.BUILD_NUMBER}"
        RED        = 'devsecops'
        TOOLS      = '/opt/sec/bin'
        EVIDENCIAS = "/evidencias/build-${env.BUILD_NUMBER}"
        ZAP_IMAGE  = 'zaproxy/zap-stable'
    }

    stages {

        stage('1. Checkout y trazabilidad') {
            steps {
                checkout scm
                sh '''
                    rm -rf reports && mkdir -p reports
                    {
                      echo "===== TRAZABILIDAD DEL BUILD ====="
                      echo "Job        : ${JOB_NAME}"
                      echo "Build      : #${BUILD_NUMBER}"
                      echo "Fecha      : $(date '+%Y-%m-%d %H:%M:%S %Z')"
                      echo "Repositorio: $(git config --get remote.origin.url)"
                      echo "Commit     : $(git rev-parse HEAD)"
                      echo "Autor      : $(git log -1 --pretty='%an <%ae>')"
                      echo "Mensaje    : $(git log -1 --pretty=%s)"
                      echo ""
                      echo "Hash SHA-256 de los archivos analizados:"
                      sha256sum app.py requirements.txt Dockerfile
                    } > reports/00-trazabilidad.txt
                    cat reports/00-trazabilidad.txt
                '''
            }
        }

        stage('2. Pruebas SAST - Bandit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        ${TOOLS}/bandit -r . -x ./reports -f html -o reports/01-bandit.html || true
                        ${TOOLS}/bandit -r . -x ./reports -f txt  -o reports/01-bandit.txt  || true
                        cat reports/01-bandit.txt
                        # Puerta de seguridad: falla si hay hallazgos de severidad MEDIA o ALTA
                        ${TOOLS}/bandit -r . -x ./reports -ll -q
                    '''
                }
            }
        }

        stage('3. Pruebas SAST - Semgrep') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        ${TOOLS}/semgrep scan --config semgrep-rules.yml --metrics=off --disable-version-check \
                            --json --output reports/02-semgrep.json . || true
                        ${TOOLS}/semgrep scan --config semgrep-rules.yml --metrics=off --disable-version-check \
                            --error . > reports/02-semgrep.txt 2>&1
                        rc=$?
                        cat reports/02-semgrep.txt
                        exit $rc
                    '''
                }
            }
        }

        stage('4. Gestion de dependencias - pip-audit') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        ${TOOLS}/pip-audit -r requirements.txt --no-deps --disable-pip --desc \
                            -f markdown -o reports/03-pip-audit.md || true
                        ${TOOLS}/pip-audit -r requirements.txt --no-deps --disable-pip > reports/03-pip-audit.txt 2>&1
                        rc=$?
                        cat reports/03-pip-audit.txt
                        exit $rc
                    '''
                }
            }
        }

        stage('5. Construccion - Docker build') {
            steps {
                sh '''
                    docker build -t ${IMAGE} -t ${APP_NAME}:latest \
                        --label securedev.build=${BUILD_NUMBER} \
                        --label securedev.commit=$(git rev-parse HEAD) .
                    docker image inspect ${IMAGE} --format 'Imagen: {{.RepoTags}}  ID: {{.Id}}  Usuario: "{{.Config.User}}"' \
                        | tee reports/04-imagen.txt
                '''
            }
        }

        stage('6. Despliegue') {
            steps {
                sh '''
                    docker rm -f ${APP_NAME} >/dev/null 2>&1 || true
                    docker run -d --name ${APP_NAME} --network ${RED} -p 5000:5000 \
                        --restart unless-stopped \
                        --label securedev.build=${BUILD_NUMBER} \
                        --label securedev.commit=$(git rev-parse HEAD) \
                        ${IMAGE}

                    # Espera a que la app responda
                    for i in $(seq 1 30); do
                        if curl -s -o /dev/null http://${APP_NAME}:5000/hello?name=test; then break; fi
                        sleep 2
                    done
                    echo "Respuesta de la app desplegada:" | tee reports/05-despliegue.txt
                    curl -s -i "http://${APP_NAME}:5000/hello?name=Jenkins" | tee -a reports/05-despliegue.txt
                    echo "" | tee -a reports/05-despliegue.txt
                    docker ps --filter name=${APP_NAME} --format 'Contenedor: {{.Names}}  Imagen: {{.Image}}  Estado: {{.Status}}' \
                        | tee -a reports/05-despliegue.txt
                '''
            }
        }

        stage('7. Pruebas DAST - OWASP ZAP') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        docker rm -f zap-scan >/dev/null 2>&1 || true
                        docker run --name zap-scan --network ${RED} -u root -v zap-wrk:/zap/wrk:rw ${ZAP_IMAGE} \
                            zap-full-scan.py -t "http://${APP_NAME}:5000/hello?name=test" -m 1 -I \
                            -r zap-report.html -J zap-report.json \
                            -z "-config scanner.maxScanDurationInMins=8" || true
                        docker cp zap-scan:/zap/wrk/zap-report.html reports/06-zap-report.html
                        docker cp zap-scan:/zap/wrk/zap-report.json reports/06-zap-report.json
                        docker rm -f zap-scan >/dev/null 2>&1 || true

                        # Resumen + puerta de seguridad: falla si ZAP encuentra alertas de riesgo ALTO
                        python3 /opt/scripts/resumen_zap.py reports/06-zap-report.json | tee reports/06-zap-resumen.txt
                        exit $(python3 /opt/scripts/resumen_zap.py reports/06-zap-report.json --exit-code)
                    '''
                }
            }
        }
    }

    post {
        always {
            sh '''
                mkdir -p ${EVIDENCIAS}
                cp -r reports/. ${EVIDENCIAS}/ || true
            '''
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh '''
                    REG=/evidencias/registro-pipeline.csv
                    [ -f $REG ] || echo 'build;fecha;commit;mensaje;resultado' > $REG
                    MSG=$(git log -1 --pretty=%s | tr ';' ',')
                    echo "${BUILD_NUMBER};$(date '+%Y-%m-%d %H:%M:%S');$(git rev-parse --short HEAD);${MSG};${RESULTADO}" >> $REG
                    echo "Registro de trazabilidad actualizado:"; cat $REG
                '''
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
        }
        success  { echo 'RESULTADO: pipeline OK - sin vulnerabilidades bloqueantes' }
        unstable { echo 'RESULTADO: se encontraron vulnerabilidades - revisar reportes en evidencias/' }
        failure  { echo 'RESULTADO: el pipeline fallo' }
    }
}
