{
    "targets": [
        {
            "target_name": "rijndael",
            "dependencies": [
                "lib/libmcrypt/libmcrypt.gyp:libmcrypt",
            ],
            "sources": [
                "src/rijndael.cc"
            ],
            "include_dirs": [
                "lib/libmcrypt/include/",
                "<!(node -e \"require('nan')\")"
            ]
        }
    ]
}
