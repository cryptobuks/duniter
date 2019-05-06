#!/usr/bin/env bash

GT_TARGET_BLOCK=210000 # This is a fixed block# which determines to the sha1 hashes
GT_BINDEX_CS=2180041597ef05aa8defc757a16fe955355960ba
GT_IINDEX_CS=dfd2dfc3d4d0ced4c101badb4d4a1ab85de8cbde
GT_MINDEX_CS=d867b887663cdfad8ac42dacc6081d638eea0976
GT_CINDEX_CS=8e02e450943add3935031df8e6608cfb4bf015d3
GT_SINDEX_CS=7c6801027e39b9fea9be973d8773ac77d2c9a1f9

.gitlab/test/check_indexes.sh /tmp/duniter_ci_dump/ gt ${GT_TARGET_BLOCK} ${GT_BINDEX_CS} ${GT_IINDEX_CS} ${GT_MINDEX_CS} ${GT_CINDEX_CS} ${GT_SINDEX_CS}
