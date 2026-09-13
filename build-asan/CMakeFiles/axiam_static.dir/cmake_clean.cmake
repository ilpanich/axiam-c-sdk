file(REMOVE_RECURSE
  "libaxiam.a"
  "libaxiam.pdb"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/axiam_static.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
