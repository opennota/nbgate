nbgate [![License](http://img.shields.io/:license-gpl3-blue.svg)](http://www.gnu.org/licenses/gpl-3.0.html) [![Build Status](https://travis-ci.org/opennota/nbgate.png?branch=master)](https://travis-ci.org/opennota/nbgate)
======

nbgate is a reverse proxy to [notabenoid.org](http://notabenoid.org). It provides access to the site under a single common account while preventing the account from being hijacked.

## Install

    go get -u github.com/opennota/nbgate

## Run

    nbgate -u username -p password
