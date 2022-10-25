FROM debian:latest

RUN apt update
RUN apt install -y \
        build-essential \
        latexmk \
        texlive \
        texlive-science \
        texlive-fonts-extra \
        texlive-bibtex-extra

ENTRYPOINT ["make"]
