#!/usr/bin/env bash

for FILE in dist/scan4all_*/*; do
    du -sh ${FILE}
    upx ${FILE}
    du -sh ${FILE}
done