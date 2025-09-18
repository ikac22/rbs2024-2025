SQUBE_DIR=$(dirname $0)

docker run -d --name sonarqube -p 9000:9000 \
           -v ${SQUBE_DIR}/sonarqube_data:/opt/sonarqube/data \
           -v ${SQUBE_DIR}/sonarqube_extensions:/opt/sonarqube/extensions \
           -v ${SQUBE_DIR}/sonarqube_logs:/opt/sonarqube/logs \
           sonarqube:lts-community
