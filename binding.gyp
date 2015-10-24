{
    "targets": [
        {
            "target_name": "rijndael",
            "sources": ["src/Rijndael.cc", "src/rijndael.cc"],
            "link_settings": {
                "libraries": ["-lmcrypt"]
            },
            "include_dirs": ["<!(node -e \"require('nan')\")"],
            'conditions': [
                ['OS=="mac"', {
                    'include_dirs': ['/usr/local/include'],
                    'library_dirs': ['/usr/local/lib'],
                }],
            ]
        }
    ]
}
