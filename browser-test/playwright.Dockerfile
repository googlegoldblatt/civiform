FROM mcr.microsoft.com/playwright:focal

ENV PROJECT_DIR /usr/src/civiform-browser-tests

RUN apt-get update && apt-get install -y --no-install-recommends postgresql-client-12

COPY . ${PROJECT_DIR}
RUN cd ${PROJECT_DIR} && yarn install

WORKDIR $PROJECT_DIR

ENV TINI_VERSION v0.19.0
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini

ENTRYPOINT ["/tini", "--"]

CMD ["/usr/src/civiform-browser-tests/bin/wait_for_server_start_and_run_tests.sh"]