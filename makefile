PDFNAME=sigma

all: $(PDFNAME).pdf

$(PDFNAME).pdf: $(wildcard *.tex) $(wildcard *.bib) $(wildcard assets/*)
	latexmk -pdflatex $(PDFNAME).tex

clean:
	rm -f *.toc *.aux *.dvi *.log *.out *.pdf *.xcp *.bbl *.blg
