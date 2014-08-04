{
    "targets": [
        {
            "target_name": "rijndael",
            "sources": ["src/rijndael.cc"],
            "link_settings": {
                "libraries": ["-lmcrypt"]
            },
            "include_dirs": ["<!(node -e \"require('nan')\")"]
        }
    ]
}
