FROM ubuntu:22.04

ENV user ctf
ENV prob_port 10101
ENV binary=flagishere
ENV TERM=linux

RUN useradd $user
RUN mkdir /home/$user
RUN sed -i 's/archive.ubuntu.com/mirror.kakao.com/g' /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y socat

ADD src/$binary /home/$user/$binary
ADD src/libcrypto.so.3 /lib/x86_64-linux-gnu
ADD src/flag /flag
ADD src/readflag /readflag
RUN chmod 400 /flag
RUN chmod 4755 /readflag
RUN chown root:$user /home/$user
RUN chmod 755 /home/$user/$binary

CMD socat -T 300 TCP-LISTEN:$prob_port,reuseaddr,fork EXEC:/home/$user/$binary
USER $user
EXPOSE $prob_port