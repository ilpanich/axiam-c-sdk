file(REMOVE_RECURSE
  ".1"
  "libaxiam.pdb"
  "libaxiam.so"
  "libaxiam.so.1"
  "libaxiam.so.1.0.0"
)

# Per-language clean rules from dependency scanning.
foreach(lang C)
  include(CMakeFiles/axiam.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
