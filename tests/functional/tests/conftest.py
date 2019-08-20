# coding: utf-8
"""Configurations for py.test runner"""

from ctrlibrary.core import settings


def pytest_collection_modifyitems():
    if not settings.configured:
        settings.configure()
    return settings
