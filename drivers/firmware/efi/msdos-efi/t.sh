#!/bin/bash

[ $1 -eq 1 ] || {
    echo failed;
    [ $2 -eq 1 ]
} && {
    echo ok;
}
