from conan import ConanFile
from conan.tools.cmake import CMake, CMakeToolchain, CMakeDeps, cmake_layout
from conan.tools.files import copy
import os


class AxiamCSdkConan(ConanFile):
    name = "axiam-c-sdk"
    version = "1.0.0-alpha12"
    license = "Apache-2.0"
    url = "https://github.com/ilpanich/axiam-c-sdk"
    description = (
        "AXIAM C SDK — REST client conforming to CONTRACT.md "
        "§1–§7, §9–§11 (incl. §6.1 mTLS)."
    )
    topics = ("iam", "authentication", "authorization", "axiam", "mtls")
    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True, False]}
    default_options = {"shared": False, "fPIC": True}

    # Consistent with CMakeLists.txt find_package(CURL)/find_package(OpenSSL).
    requires = ("libcurl/8.6.0", "openssl/3.2.1")

    exports_sources = (
        "CMakeLists.txt",
        "cmake/*",
        "include/*",
        "src/*",
        "third_party/*",
        "LICENSE",
        "CONTRACT.md",
    )

    def config_options(self):
        if self.settings.os == "Windows":
            del self.options.fPIC

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.variables["AXIAM_BUILD_TESTS"] = "OFF"
        # examples/ is not part of the packaged sources (not in exports_sources),
        # so keep the sample programs out of the Conan build.
        tc.variables["AXIAM_BUILD_EXAMPLES"] = "OFF"
        tc.variables["AXIAM_BUILD_SHARED"] = "ON" if self.options.shared else "OFF"
        tc.variables["AXIAM_BUILD_STATIC"] = "OFF" if self.options.shared else "ON"
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()
        copy(self, "LICENSE", src=self.source_folder,
             dst=os.path.join(self.package_folder, "licenses"))

    def package_info(self):
        self.cpp_info.libs = ["axiam"]
        self.cpp_info.set_property("cmake_file_name", "axiam-c-sdk")
        self.cpp_info.set_property("cmake_target_name", "axiam::axiam")
        if self.settings.os in ("Linux", "FreeBSD"):
            self.cpp_info.system_libs = ["pthread"]
