#!/usr/bin/env python3

# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import sys
import os
import asyncio
import numpy as np
import pandas as pd
from pandas import DataFrame as df
import hashlib

from PyQt5 import QtCore
from PyQt5.QtCore import QThread
from PyQt5.QtCore import QObject
from PyQt5 import QtGui
from PyQt5 import QtWidgets

from PyQt5.QtCore import QAbstractTableModel, Qt
# from PyQt5.QtCore import pyqtSignal
# from PyQt5.QtCore import pyqtSlot
from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QMainWindow
from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QTableWidget
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtWidgets import QInputDialog
from PyQt5.QtWidgets import QLineEdit
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtWidgets import QTableView
from PyQt5.QtWidgets import QMessageBox

# Mmmmm... Hashbrowns...
class Hashbrown_Machine(QMainWindow, QObject):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.options = QFileDialog.Options()

        selectedInputFile, _= QFileDialog.getOpenFileName(None, "Select Input File", "", "All Files (*)", options=self.options)

        if selectedInputFile:
            md5_hashbrown = hashlib.md5()
            sha1_hashbrown = hashlib.sha1()
            sha256_hashbrown = hashlib.sha256()
            sha512_hashbrown = hashlib.sha512()
            with open(selectedInputFile, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    md5_hashbrown.update(chunk)
                    self.digestedMD5_hashbrown = md5_hashbrown.hexdigest()
                    sha1_hashbrown.update(chunk)
                    self.digestedSHA1_hashbrown = sha1_hashbrown.hexdigest()
                    sha256_hashbrown.update(chunk)
                    self.digestedSHA256_hashbrown = sha256_hashbrown.hexdigest()
                    sha512_hashbrown.update(chunk)
                    self.digestedSHA512_hashbrown = sha512_hashbrown.hexdigest()

            self.datAzz = f"md5 Hash = {self.digestedMD5_hashbrown}\nsha1 = {self.digestedSHA1_hashbrown}\nsha256 = {self.digestedSHA256_hashbrown}\nsha512 = {self.digestedSHA512_hashbrown}"
            MsgBox("Test Message Box", "information", self.datAzz)

    # Generate and outputs md5 hash of selected input file
    def md5_hashbrownMaker(self, selectedInputFile):
        md5_hashbrown = hashlib.md5()
        with open(selectedInputFile, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hashbrown.update(chunk)
        self.digestedMD5_hashbrown = md5_hashbrown.hexdigest()

    # Generate and outputs sha1 hash of selected input file
    def sha1_hashbrownMaker(self, selectedInputFile):
        sha1_hashbrown = hashlib.sha1()
        with open(selectedInputFile, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha1_hashbrown.update(chunk)
        self.digestedSHA1_hashbrown = sha1_hashbrown.hexdigest()

    # Generate and outputs sha256 hash of selected input file
    def sha256_hashbrownMaker(self, selectedInputFile):
        sha256_hashbrown = hashlib.sha256()
        with open(selectedInputFile, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hashbrown.update(chunk)
        self.digestedSHA256_hashbrown = sha256_hashbrown.hexdigest()

    # Generate and outputs sha512 hash of selected input file
    def sha512_hashbrownMaker(self, selectedInputFile):
        sha512_hashbrown = hashlib.sha512()
        with open(selectedInputFile, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha512_hashbrown.update(chunk)
        self.digestedSHA512_hashbrown = sha512_hashbrown.hexdigest()

    # def aes256_hashbrownMaker(self, selectedInputFile):
    #     aes256_hashbrown = hashlib.aes256()


class TableView(QTableWidget):
    def __init__(self, data, *args):
        QTableWidget.__init__(self, *args)
        self.data = data
        self.setData()
        self.resizeColumnsToContents()
        self.resizeRowsToContents()
    def setData(self):
        horHeaders = []
        # for n, key in enumerate(sorted(self.data.keys())):
        for n, key in enumerate(self.data.keys()):
            horHeaders.append(key)
            for m, item in enumerate(self.data[key]):
                newitem = QTableWidgetItem(item)
                self.setItem(m, n, newitem)
        self.setHorizontalHeaderLabels(horHeaders)


class MsgBox(QMessageBox):
    # The Message Box
    def __init__(self, title, msgType, message):
        super().__init__()
        # set message box type according to the 'type' requested
        if "crititcal" in msgType:
            self.setIcon(QMessageBox.Critical)
        if "warning" in msgType:
            self.setIcon(QMessageBox.Warning)
        if "information" in msgType:
            self.setIcon(QMessageBox.Information)
        if "question" in msgType:
            self.setIcon(QMessageBox.Question)
        # Set the message box title
        self.setWindowTitle(title)
        # Set the message box message
        self.setText(message)
        # Display the message box
        sys.exit(self.exec_())


if __name__ == "__main__":

    Hashbrowns = QApplication(sys.argv)

    ui = Hashbrown_Machine()
    # ui.setupUi(SebastianLeadsForm)
    ui.show()

    # Start the GUI event loop
    sys.exit(Hashbrowns.exec_())
