// =====================================================================
//  Pipeline DevSecOps - SecureDev (OCY1102)
//  Etapas: Checkout -> Build -> Test -> Analyze (SonarQube)
//          -> Dependencias (pip-audit + OWASP Dependency-Check)
//          -> Deploy -> Security Test (OWASP ZAP) -> Trazabilidad
//  Las herramientas de seguridad se ejecutan como contenedores Docker
//  (Jenkins usa el Docker del equipo a traves de /var/run/docker.sock).
// =====================================================================
pipeline {
    agent any

    parameters {
        booleanParam(name: 'RUN_DEPENDENCY_CHECK', defaultValue: true,
            description: 'Ejecutar OWASP Dependency-Check (la 1a vez descarga la base NVD y puede tardar)')
        booleanParam(name: 'RUN_ZAP', defaultValue: true,
            description: 'Ejecutar escaneo dinamico con OWASP ZAP')
    }

    options {
        timestamps()
        buildDiscarder(logRotator(numToKeepStr: '30'))
        timeout(time: 90, unit: 'MINUTES')
    }

    environment {
        APP_NAME   = 'securedev-app'
        IMAGE_TAG  = "securedev-app:${BUILD_NUMBER}"
        NET        = 'devsecops'
        SONAR_HOST = 'http://sonarqube:9000'
        APP_URL    = 'http://securedev-app:5000'
    }

    stages {

        stage('Checkout') {
            steps {
                checkout scm
                sh '''
                    mkdir -p reports
                    echo "Commit:  $(git rev-parse HEAD)"                 >  reports/trazabilidad.txt
                    echo "Autor:   $(git log -1 --pretty=format:'%an')"  >> reports/trazabilidad.txt
                    echo "Mensaje: $(git log -1 --pretty=format:'%s')"   >> reports/trazabilidad.txt
                    echo "Build:   ${BUILD_NUMBER}  (${BUILD_URL})"      >> reports/trazabilidad.txt
                    echo "Fecha:   $(date '+%Y-%m-%d %H:%M:%S')"         >> reports/trazabilidad.txt
                '''
            }
        }

        stage('Build') {
            steps {
                sh '''
                    python3 -m venv .venv
                    . .venv/bin/activate
                    pip install -q --upgrade pip
                    pip install -q -r requirements.txt -r requirements-dev.txt
                '''
                sh 'docker build -t ${IMAGE_TAG} -t ${APP_NAME}:latest .'
                sh 'echo "Imagen:  ${IMAGE_TAG}  $(docker image inspect ${IMAGE_TAG} --format "{{.Id}}")" >> reports/trazabilidad.txt'
            }
        }

        stage('Test') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        . .venv/bin/activate
                        pytest -v --junitxml=reports/junit.xml
                    '''
                }
            }
            post {
                always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' }
            }
        }

        stage('Analyze - SonarQube') {
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    withCredentials([string(credentialsId: 'sonar-token', variable: 'SONAR_TOKEN')]) {
                        sh '''
                            docker run --rm -u root --network ${NET} --volumes-from jenkins \
                              -w "${WORKSPACE}" \
                              -e SONAR_HOST_URL=${SONAR_HOST} -e SONAR_TOKEN \
                              sonarsource/sonar-scanner-cli \
                              -Dsonar.projectBaseDir="${WORKSPACE}"
                        '''
                    }
                }
            }
        }

        stage('Dependencias (SCA)') {
            steps {
                // pip-audit: base de vulnerabilidades de PyPI / OSV (rapido)
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        . .venv/bin/activate
                        mkdir -p reports/pip-audit
                        pip-audit -r requirements.txt -f json     -o reports/pip-audit/pip-audit.json || true
                        pip-audit -r requirements.txt -f markdown -o reports/pip-audit/pip-audit.md   || true
                        pip-audit -r requirements.txt --desc
                    '''
                }
                // OWASP Dependency-Check: base NVD
                script {
                    if (params.RUN_DEPENDENCY_CHECK) {
                        catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                            sh '''
                                mkdir -p reports/dependency-check
                                NVD_ARG=""
                                if [ -n "${NVD_API_KEY}" ]; then NVD_ARG="--nvdApiKey ${NVD_API_KEY}"; fi
                                docker run --rm -u root --volumes-from jenkins \
                                  -v dc-data:/usr/share/dependency-check/data \
                                  owasp/dependency-check:latest \
                                  --project "securedev" \
                                  --scan "${WORKSPACE}/requirements.txt" \
                                  --enableExperimental \
                                  --format HTML --format JSON --format XML \
                                  --out "${WORKSPACE}/reports/dependency-check" \
                                  ${NVD_ARG}
                            '''
                            dependencyCheckPublisher pattern: 'reports/dependency-check/dependency-check-report.xml'
                        }
                    }
                }
            }
        }

        stage('Deploy') {
            steps {
                sh '''
                    docker rm -f ${APP_NAME} || true
                    docker run -d --name ${APP_NAME} --network ${NET} -p 5000:5000 \
                      --restart unless-stopped ${APP_NAME}:latest
                    sleep 8
                    docker run --rm --network ${NET} curlimages/curl -sf "${APP_URL}/hello?name=Jenkins"
                    echo ""
                    echo "Desplegado: ${IMAGE_TAG} en http://localhost:5000" >> reports/trazabilidad.txt
                '''
            }
        }

        stage('Security Test - OWASP ZAP') {
            when { expression { return params.RUN_ZAP } }
            steps {
                catchError(buildResult: 'UNSTABLE', stageResult: 'FAILURE') {
                    sh '''
                        docker rm -f zap-scan || true
                        docker run --name zap-scan --network ${NET} zaproxy/zap-stable \
                          bash -c "mkdir -p /zap/wrk && zap-full-scan.py \
                                   -t '${APP_URL}/hello?name=test' -m 1 -I \
                                   -r zap-report.html -J zap-report.json -w zap-report.md" || true
                        mkdir -p reports/zap
                        docker cp zap-scan:/zap/wrk/zap-report.html reports/zap/
                        docker cp zap-scan:/zap/wrk/zap-report.json reports/zap/
                        docker cp zap-scan:/zap/wrk/zap-report.md   reports/zap/
                        docker rm -f zap-scan
                        echo "===== Resumen ZAP ====="
                        cat reports/zap/zap-report.md | head -60
                    '''
                }
            }
        }
    }

    post {
        always {
            sh "echo 'Resultado: ${currentBuild.currentResult}' >> reports/trazabilidad.txt || true"
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [reportName: 'OWASP ZAP', reportDir: 'reports/zap',
                reportFiles: 'zap-report.html', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
            publishHTML(target: [reportName: 'Dependency-Check', reportDir: 'reports/dependency-check',
                reportFiles: 'dependency-check-report.html', keepAll: true, alwaysLinkToLastBuild: true, allowMissing: true])
        }
    }
}
