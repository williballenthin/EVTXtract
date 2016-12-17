import os

import pytest

import evtxtract.utils


CD = os.path.dirname(__file__)
IMAGE_PATH = os.path.join(CD, 'joshua1.vmem')


@pytest.fixture
def image(request):
    if not os.path.exists(IMAGE_PATH):
        raise RuntimeError('required image %s does not exist. see readme.' % (IMAGE_PATH))

    return IMAGE_PATH


@pytest.fixture
def image_file(request):
    with open(image(request), 'rb') as f:
        yield f


@pytest.fixture
def image_mmap(request):
    with evtxtract.utils.Mmap(image(request)) as mm:
        yield mm

