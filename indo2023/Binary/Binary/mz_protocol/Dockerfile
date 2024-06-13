FROM ubuntu@sha256:ca5534a51dd04bbcebe9b23ba05f389466cf0c190f1f8f182d7eea92a9671d00

ENV user ctf
ENV prob_port 10001
ENV binary=mz_protocol
ENV TERM=linux

RUN useradd ctf
RUN apt-get update
RUN apt-get install -y socat

ADD src/$binary /home/$user/
ADD src/flag.txt /home/$user/
RUN chown root:$user /home/$user/flag.txt
RUN chmod 440 /home/$user/*
RUN chmod +x /home/$user/$binary
RUN mv /home/$user/flag.txt /flag.txt

CMD socat -T 30 TCP-LISTEN:$prob_port,reuseaddr,fork EXEC:/home/$user/$binary
USER $user
EXPOSE $prob_port