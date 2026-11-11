
pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
    }

    environment {
    PATH = "C:/Python313;C:/Python313/Scripts;C:/Program Files/nodejs;C:/Program Files/Git/cmd;${env.PATH}"
}

    stages {

        stage('1. GitHub Checkout') {
            steps {
                checkout scm
                echo 'Successfully downloaded project from GitHub.'
            }
        }

        stage('2. Verify Tools') {
            steps {
                bat 'python --version'
                bat 'node --version'
                bat 'npm --version'
                bat 'git --version'
            }
        }

        stage('3. Backend Dependencies') {
            steps {
                dir('backend') {
                    bat 'python -m pip install --upgrade pip'
                    bat 'python -m pip install -e ".[dev]"'
                }
            }
        }

        stage('4. Backend Code Quality') {
            steps {
                dir('backend') {
                    bat 'ruff check app tests'
                    bat 'black --check app tests'
                    bat 'mypy app'
                }
            }
        }

        stage('5. Backend Testing') {
            steps {
                dir('backend') {
                    bat 'pytest --cov=app --cov-fail-under=70'
                }
            }
        }

        stage('6. Backend Security') {
            steps {
                dir('backend') {
                    bat 'bandit -q -r app'
                    bat 'pip-audit --skip-editable'
                }
            }
        }

        stage('7. Frontend Dependencies') {
            steps {
                dir('frontend') {
                    bat 'npm ci'
                }
            }
        }

        stage('8. Frontend Linting') {
            steps {
                dir('frontend') {
                    bat 'npm run lint'
                }
            }
        }

        stage('9. Frontend Testing') {
            steps {
                dir('frontend') {
                    bat 'npm test'
                }
            }
        }

        stage('10. Frontend Production Build') {
            steps {
                dir('frontend') {
                    bat 'npm run build'
                }
            }
        }
    }

    post {
        success {
            echo 'SUCCESS: All IVM CI pipeline stages passed!'
        }

        failure {
            echo 'FAILURE: Check the Jenkins Console Output for details.'
        }

        always {
            echo 'IVM Jenkins Pipeline execution completed.'
        }
    }
}
