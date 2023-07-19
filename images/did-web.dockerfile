FROM gleif/keri:latest

EXPOSE 7676

WORKDIR /usr/local/var

RUN mkdir keri
COPY ./db/keri /usr/local/var/keri

RUN mkdir did-keri-resolver
COPY . /usr/local/var/did-keri-resolver

WORKDIR /usr/local/var/did-keri-resolver

RUN pip install -r requirements.txt

CMD ["/usr/local/var/did-keri-resolver/scripts/did-web.sh"]