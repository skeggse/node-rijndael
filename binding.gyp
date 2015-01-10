{
  'targets': [
    {
      'target_name': 'rijndael',
      'sources': ['src/rijndael.cc'],
      'dependencies': [
        'deps/libmcrypt/libmcrypt.gyp:mcrypt'
      ],
      'include_dirs': ['<!(node -e "require(\'nan\')")']
    }
  ]
}
