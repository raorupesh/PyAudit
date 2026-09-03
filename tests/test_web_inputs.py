from io import BytesIO

from pyaudit.web.app import _prepare_scan_target


class FakeUpload:
    def __init__(self, filename, payload):
        self.filename = filename
        self.payload = payload

    def save(self, destination):
        with open(destination, "wb") as fh:
            fh.write(self.payload)


def test_prepare_scan_target_accepts_snippet():
    target = _prepare_scan_target("", "", "print('hello')\n", None)

    assert target.is_dir()
    assert (target / "app.py").read_text(encoding="utf-8") == "print('hello')"


def test_prepare_scan_target_accepts_uploaded_python_file():
    uploaded = FakeUpload("demo.py", b"print('uploaded')\n")

    target = _prepare_scan_target("", "", "", uploaded)

    assert target.is_dir()
    assert (target / "demo.py").read_text(encoding="utf-8") == "print('uploaded')\n"
