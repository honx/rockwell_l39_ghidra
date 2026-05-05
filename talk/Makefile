# Makefile for the CCC Congress talk.
#
# Targets:
#   make            -> slides.pdf (slides only, no notes)
#   make notes      -> slides-notes.pdf (slides + speaker notes pages, side-by-side)
#   make handout    -> slides-handout.pdf (handout mode, no overlays, no notes)
#   make all        -> all three PDFs above
#   make clean      -> remove build artefacts
#   make distclean  -> remove build artefacts and final PDFs
#
# Requires: pdflatex + beamer + metropolis theme. On Debian/Ubuntu:
#   apt install texlive-latex-base texlive-latex-extra texlive-fonts-extra \
#               texlive-pictures texlive-science texlive-luatex texlive-xetex \
#               texlive-publishers texlive-bibtex-extra
# Or just `apt install texlive-full` if you don't care about disk space.

LATEX      := pdflatex
LATEXFLAGS := -interaction=nonstopmode -halt-on-error -file-line-error
BUILDDIR   := build

# Two-pass build to resolve cross-references and TOC. Beamer normally
# needs only two passes; we run three to be safe with overlays.
# Argument $(3) is a TeX prefix that gets prepended to \input{...}.
define run_pdflatex
	@mkdir -p $(BUILDDIR)
	$(LATEX) $(LATEXFLAGS) -output-directory=$(BUILDDIR) -jobname=$(2) \
		"$(3)\input{$(1)}" >/dev/null
	$(LATEX) $(LATEXFLAGS) -output-directory=$(BUILDDIR) -jobname=$(2) \
		"$(3)\input{$(1)}" >/dev/null
	$(LATEX) $(LATEXFLAGS) -output-directory=$(BUILDDIR) -jobname=$(2) \
		"$(3)\input{$(1)}"
	cp $(BUILDDIR)/$(2).pdf .
endef

.PHONY: all slides notes handout clean distclean

all: slides notes handout

slides: slides.pdf

notes: slides-notes.pdf

handout: slides-handout.pdf

# Title graphic is built once and reused by every variant.
title-graphic.pdf: title-graphic.tex
	@mkdir -p $(BUILDDIR)
	$(LATEX) $(LATEXFLAGS) -output-directory=$(BUILDDIR) title-graphic.tex >/dev/null
	cp $(BUILDDIR)/title-graphic.pdf .

# Slides only — default output.
slides.pdf: slides.tex title-graphic.pdf
	$(call run_pdflatex,slides.tex,slides,)

# Slides with speaker notes on a second screen pane (right-hand side).
# The \notesmode flag is read by slides.tex to enable
# `\setbeameroption{show notes on second screen=right}`.
slides-notes.pdf: slides.tex title-graphic.pdf
	$(call run_pdflatex,slides.tex,slides-notes,\def\notesmode{1})

# Handout: every overlay collapsed to one page, no animations, no notes.
# The wrapper sets `\PassOptionsToClass{handout}{beamer}` before \input.
slides-handout.pdf: slides.tex title-graphic.pdf
	$(call run_pdflatex,slides.tex,slides-handout,\PassOptionsToClass{handout}{beamer})

clean:
	rm -rf $(BUILDDIR)

distclean: clean
	rm -f slides.pdf slides-notes.pdf slides-handout.pdf title-graphic.pdf
