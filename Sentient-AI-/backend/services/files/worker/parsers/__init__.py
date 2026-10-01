"""One parser per document family, run only inside the worker process.

Why it exists: each parser turns one kind of file into protocol lines (units
of text, scanned pages, warnings) under the worker's limits. They are pure
Python (pypdf, openpyxl, zipfile with defusedxml, csv) except Pillow for
images, and none imports the app.
"""
