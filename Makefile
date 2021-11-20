run:
	@LISTEN_ADDR="0.0.0.0" \
		LISTEN_PORT="8090" \
		REMOTE_ADDR="127.0.01" \
		REMOTE_PORT="5432" \
		QUERY_FILTER="true" \
		LOG_LEVEL="debug" \
		python3 src/app.py

build:
	@docker build --tag postgresrelay:0.0.1 -f docker/Dockerfile .

docker:
	@docker build --tag postgresrelay:0.0.1 -f docker/Dockerfile .
	@docker run \
		--rm \
		--name=postgresrelay \
		--hostname=postgresrelay \
		--net=host \
		--publish 8090:8090 \
		-e REMOTE_ADDR=127.0.0.1 \
		-e LOG_LEVEL=debug \
		-v ${PWD}/config/config.yaml:/etc/postgresrelay/config.yaml \
		-v ${PWD}/data/postgres_queries.log:/var/log/postgresrelay_persistent/postgres_queries.log \
		postgresrelay:0.0.1
