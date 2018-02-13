.PHONY: wheel docs

PYTHON3="python3.5"
DOCS_DEST="./dist/docs"
API_DOCS="./docs/api-doc"

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

docs:
	@echo "Start generating docs"


	@echo "Generate Api Docs"
	$(call clean_api_docs)
	sphinx-apidoc -f --no-toc -o ${API_DOCS} ./virgil_sdk


	@echo "Check ${DOCS_DEST} exist"
	@if [ -d ./dist ]; then \
		if [ ! -d ${DOCS_DEST} ]; then \
			mkdir ${DOCS_DEST}; \
		fi \
	else \
		mkdir -p ${DOCS_DEST}; \
	fi


	sphinx-build ./docs ${DOCS_DEST}

wheel:
	${PYTHON3} setup.py bdist_wheel --universal --python-tag py2.py3
	$(call clean_after_wheel)


upload_testpypi:
	# old style
#	${PYTHON3} setup.py register -r pypitest
#	${PYTHON3} setup.py bdist upload -r pypitest

	# new style
	twine upload -r pypitest dist/*

clean:
	$(call clean_api_docs)
	$(call clean_dist)
