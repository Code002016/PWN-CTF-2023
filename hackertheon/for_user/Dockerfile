FROM swathip2021/myubuntu:20.04
#FROM ubuntu:20.04
ENV PROB_NAME go_flag
ENV PORT 4242
RUN apt-get -y update
RUN apt-get -y install socat
RUN mkdir /home/${PROB_NAME}
RUN useradd ${PROB_NAME} -d /home/${PROB_NAME}

ADD flag /flag
ADD ${PROB_NAME} /home/${PROB_NAME}
ADD start.sh /home/${PROB_NAME}/start.sh

WORKDIR /home/${PROB_NAME}

RUN chmod 755 start.sh

USER ${PROB_NAME}

CMD ["./start.sh"]
EXPOSE ${PORT}

