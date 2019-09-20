.PHONY: wheel docs

PYTHON3="python3.5"
REPO=VirgilSecurity/virgil-sdk-python
REPO_PATH=https://github.com/${REPO}.git
DOCS_DEST="./docs"
API_DOCS="./doc-source/api-doc"
CURRENT_VERSION_DIR="${DOCS_DEST}/${GIT_TAG}"

define clean_api_docs
	@echo "Clean api-docs directory"
	@if [ -d ${API_DOCS} ]; then \
    	rm -r ${API_DOCS}; \
	fi
endef

define clean_dist
	@echo "Clean docs directory"
	@if [ -d ./dist ]; then \
		rm -r ./dist; \
	fi
endef

define clean_after_wheel
	@echo "Cleaning after wheel build"
	rm -r ./build
	rm -r ./*.egg-info
endef

sphinx_docs:
	@echo ">>> Generate Api Docs"
	$(call clean_api_docs)
	${PYTHON3} -m pip install sphinx sphinx-rtd-theme
	sphinx-apidoc -f -e -R ${GIT_TAG} -V ${GIT_TAG} -o ${API_DOCS} ./virgil_sdk *test*

	@echo "Check ${DOCS_DEST} exist"
	@if [ -d ${API_DOCS} ]; then \
		if [ ! -d ${API_DOCS} ]; then \
			mkdir ${API_DOCS}; \
		fi \
	else \
		mkdir -p ${API_DOCS}; \
	fi

	sphinx-build ./doc-source ${CURRENT_VERSION_DIR}

docs:
	@echo ">>> Start generating docs"
	mkdir -p ${DOCS_DEST}
	git clone -b gh-pages "${REPO_PATH}" --single-branch ${DOCS_DEST}
	make sphinx_docs
	${PYTHON3} -m pip install jinja2
	${PYTHON3} ci/render_index.py ${DOCS_DEST}

wheel:
	${PYTHON3} setup.py bdist_wheel --universal --python-tag py2.py3
	$(call clean_after_wheel)


upload_testpypi:
	twine upload -r pypitest dist/*

clean:
	$(call clean_api_docs)
	$(call clean_dist)