#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <jansson.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(_WIN32) || defined(_WIN64)
#include "./dirent_win.h"
#define mkdir _mkdir
#else
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#include <jansson.h>
#include <curl/curl.h>
#include <zip.h>
#include <errno.h>

#define CONFIG_FILE "app.config"
#define PACKAGE_FILE "package.json"
#define MAX_PATH_LENGTH 4096
#define MAX_DEPENDENCIES 256

typedef struct
{
    int major;
    int minor;
    int patch;
    char prerelease[20];
    char build[20];
} Version;

typedef struct
{
    char name[128];
    Version version;
} Package;

void parse_version(const char *version_str, Version *ver)
{
    const char *ptr = version_str;
    ver->major = strtol(ptr, (char **)&ptr, 10);
    if (*ptr == '.')
        ptr++;
    ver->minor = strtol(ptr, (char **)&ptr, 10);
    if (*ptr == '.')
        ptr++;
    ver->patch = strtol(ptr, (char **)&ptr, 10);

    if (*ptr == '-')
    {
        ptr++;
        sscanf(ptr, "%[^+]", ver->prerelease);
        ptr += strlen(ver->prerelease);
    }
    else
    {
        ver->prerelease[0] = '\0';
    }

    if (*ptr == '+')
    {
        ptr++;
        strcpy(ver->build, ptr);
    }
    else
    {
        ver->build[0] = '\0';
    }
}

void parse_json(const char *filename, Package *pkg)
{
    FILE *file = fopen(filename, "rb");
    if (!file)
    {
        fprintf(stderr, "Could not open file %s\n", filename);
        return;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = (char *)malloc(length + 1);
    int64_t i;
    if ((i = fread(data, 1, length, file)) < length)
    {
        return;
    }

    fclose(file);
    data[length] = '\0';

    json_error_t error;
    json_t *root = json_loads(data, 0, &error);
    free(data);

    if (!root)
    {
        fprintf(stderr, "Error parsing JSON: %s\n", error.text);
        return;
    }

    json_t *name = json_object_get(root, "name");
    json_t *version = json_object_get(root, "version");

    if (json_is_string(name) && json_is_string(version))
    {
        strcpy(pkg->name, json_string_value(name));
        parse_version(json_string_value(version), &pkg->version);
    }

    json_decref(root);
}

int compare_versions(const Version *ver1, const Version *ver2)
{
    if (ver1->major != ver2->major)
        return ver1->major - ver2->major;
    if (ver1->minor != ver2->minor)
        return ver1->minor - ver2->minor;
    if (ver1->patch != ver2->patch)
        return ver1->patch - ver2->patch;
    if (strlen(ver1->prerelease) == 0 && strlen(ver2->prerelease) > 0)
        return 1;
    if (strlen(ver1->prerelease) > 0 && strlen(ver2->prerelease) == 0)
        return -1;
    int r = strcmp(ver1->prerelease, ver2->prerelease);
    if (r != 0)
    {
        return r;
    }
    if (strlen(ver1->build) == 0 && strlen(ver2->build) > 0)
        return 1;
    if (strlen(ver1->build) > 0 && strlen(ver2->build) == 0)
        return -1;
    return strcmp(ver1->build, ver2->build);
}

void print_package_version(const Package *pkg)
{
    printf("Package %s, Version %d.%d.%d", pkg->name, pkg->version.major, pkg->version.minor, pkg->version.patch);
    if (strlen(pkg->version.prerelease) > 0)
    {
        printf("-%s", pkg->version.prerelease);
    }
    if (strlen(pkg->version.build) > 0)
    {
        printf("+%s", pkg->version.build);
    }
    printf("\n");
}

int check_package(const char *base_path, const char *pkg_name, const char *pkg_version, Package *found_pkg)
{
    DIR *dir = opendir(base_path);
    if (!dir)
    {
        fprintf(stderr, "Could not open directory %s\n", base_path);
        return 0;
    }

    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
        {
            char subdir[MAX_PATH_LENGTH + sizeof(entry->d_name) + strlen(PACKAGE_FILE)];
            snprintf(subdir, sizeof(subdir), "%s/%s/%s", base_path, entry->d_name, PACKAGE_FILE);

            Package pkg;
            parse_json(subdir, &pkg);

            if (strcmp(pkg.name, pkg_name) == 0)
            {
                *found_pkg = pkg;
                if (strlen(pkg_version) > 0)
                {
                    Version input_ver;
                    parse_version(pkg_version, &input_ver);
                    if (compare_versions(&pkg.version, &input_ver) == 0)
                    {
                        closedir(dir);
                        return 1; // Package found with matching version
                    }
                    else
                    {
                        closedir(dir);
                        return 2; // Package found but version mismatch
                    }
                }
                else
                {
                    closedir(dir);
                    return 1; // Package found, no version specified
                }
            }
        }
    }

    closedir(dir);
    return 0; // Package not found
}

void parse_input(const char *input, char *pkg_name, char *pkg_version)
{
    char *equals_sign = strchr(input, '=');
    if (equals_sign)
    {
        size_t name_len = equals_sign - input;
        strncpy(pkg_name, input, name_len);
        pkg_name[name_len] = '\0';
        strcpy(pkg_version, equals_sign + 1);
    }
    else
    {
        strcpy(pkg_name, input);
        pkg_version[0] = '\0';
    }
}

// Helper function to remove a directory recursively
int remove_directory(const char *path)
{
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d)
    {
        struct dirent *p;

        r = 0;

        while (!r && (p = readdir(d)))
        {
            int r2 = -1;
            char *buf;
            size_t len;

            // Skip the names "." and ".." as we don't want to recurse on them.
            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
            {
                continue;
            }

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf)
            {
                struct stat statbuf;

                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf))
                {
                    if (S_ISDIR(statbuf.st_mode))
                    {
                        r2 = remove_directory(buf);
                    }
                    else
                    {
                        r2 = unlink(buf);
                    }
                }

                free(buf);
            }

            r = r2;
        }

        closedir(d);
    }

    if (!r)
    {
        r = rmdir(path);
    }

    return r;
}

// Helper function to perform a HTTP GET request and save the response to a file
size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream)
{
    return fwrite(ptr, size, nmemb, stream);
}

// Function to show download progress
int progress_callback(void *clientp, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
    if (dltotal > 0)
    {
        int percent = (int)((dlnow * 100) / dltotal);
        printf("\rDownloading: %d%%", percent);
        fflush(stdout);
    }
    return 0;
}

int download_file(const char *url, const char *output_path)
{
    CURL *curl;
    FILE *fp;
    CURLcode res;

    curl = curl_easy_init();
    if (curl)
    {
        fp = fopen(output_path, "wb");
        if (!fp)
        {
            curl_easy_cleanup(curl);
            return -1;
        }
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
        curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, progress_callback);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L); // Enable progress meter
        res = curl_easy_perform(curl);
        printf("\n"); // Move to the next line after progress is complete
        curl_easy_cleanup(curl);
        fclose(fp);
        if (res != CURLE_OK)
        {
            return -1;
        }
        return 0;
    }
    return -1;
}
int file_exists(const char *path)
{
    struct stat st;
    return (stat(path, &st) == 0);
}

int create_directories(const char *dir)
{
    char tmp[MAX_PATH_LENGTH];
    snprintf(tmp, sizeof(tmp), "%s", dir);
    size_t len = strlen(tmp);
    if (tmp[len - 1] == '/')
        tmp[len - 1] = '\0';

    for (char *p = tmp + 1; *p; p++)
    {
        if (*p == '/')
        {
            *p = '\0';
            if (mkdir(tmp, 0755) && errno != EEXIST)
            {
                perror("mkdir");
                return -1;
            }
            *p = '/';
        }
    }
    if (mkdir(tmp, 0755) && errno != EEXIST)
    {
        perror("mkdir");
        return -1;
    }
    return 0;
}

int unzip_file(const char *zip_path, const char *dest_path)
{
    int err;
    struct zip *za = zip_open(zip_path, 0, &err);
    if (!za)
    {
        char errbuf[1024];
        zip_error_to_str(errbuf, sizeof(errbuf), err, errno);
        fprintf(stderr, "Failed to open zip file %s: %s\n", zip_path, errbuf);
        return -1;
    }

    for (int i = 0; i < zip_get_num_entries(za, 0); i++)
    {
        struct zip_stat st;
        zip_stat_index(za, i, 0, &st);

        char out_path[MAX_PATH_LENGTH];
        snprintf(out_path, sizeof(out_path), "%s/%s", dest_path, st.name);

        if (st.name[strlen(st.name) - 1] == '/')
        {
            if (create_directories(out_path) != 0)
            {
                fprintf(stderr, "Failed to create directory %s\n", out_path);
                zip_close(za);
                return -1;
            }
        }
        else
        {
            if (file_exists(out_path))
            {
                fprintf(stderr, "File %s already exists\n", out_path);
                continue;
            }

            struct zip_file *zf = zip_fopen_index(za, i, 0);
            if (!zf)
            {
                fprintf(stderr, "Failed to open file in zip: %s\n", zip_strerror(za));
                zip_close(za);
                return -1;
            }

            char *last_slash = strrchr(out_path, '/');
            if (last_slash)
            {
                *last_slash = '\0';
                if (create_directories(out_path) != 0)
                {
                    fprintf(stderr, "Failed to create directory for file %s\n", out_path);
                    zip_fclose(zf);
                    zip_close(za);
                    return -1;
                }
                *last_slash = '/';
            }

            FILE *out = fopen(out_path, "wb");
            if (!out)
            {
                perror("fopen");
                fprintf(stderr, "Failed to open output file %s\n", out_path);
                zip_fclose(zf);
                zip_close(za);
                return -1;
            }

            char buffer[4096];
            int bytes_read;
            while ((bytes_read = zip_fread(zf, buffer, sizeof(buffer))) > 0)
            {
                fwrite(buffer, 1, bytes_read, out);
            }

            fclose(out);
            zip_fclose(zf);
        }
    }

    zip_close(za);
    return 0;
}

void construct_url(char *url, const char *base_url, const char *direct, const char *pkg_name, const char *pkg_version)
{
    if (pkg_version && strlen(pkg_version) > 0)
    {
        snprintf(url, MAX_PATH_LENGTH, "%s/%s/%s/%s", base_url, direct, pkg_name, pkg_version);
    }
    else
    {
        snprintf(url, MAX_PATH_LENGTH, "%s/%s/%s", base_url, direct, pkg_name);
    }
}

int parse_downloaded_json(const char *json_data, Package *pkg)
{
    json_error_t error;
    json_t *root = json_loads(json_data, 0, &error);

    if (!root)
    {
        fprintf(stderr, "Error parsing downloaded JSON: %s\n", error.text);
        return -1;
    }

    json_t *name = json_object_get(root, "name");
    json_t *version = json_object_get(root, "version");

    if (json_is_string(name) && json_is_string(version))
    {
        strcpy(pkg->name, json_string_value(name));
        parse_version(json_string_value(version), &pkg->version);
    }
    else
    {
        return -1;
    }

    json_decref(root);
    return 0;
}

struct MemoryStruct
{
    char *memory;
    size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (ptr == NULL)
    {
        // out of memory!
        printf("not enough memory (realloc returned NULL)\n");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;

    return realsize;
}

int fetch_json_data(const char *url, char **json_data)
{
    CURL *curl;
    CURLcode res;
    struct MemoryStruct chunk;

    chunk.memory = malloc(1); // will be grown as needed by the realloc above
    chunk.size = 0;           // no data at this point

    curl = curl_easy_init();
    if (!curl)
    {
        free(chunk.memory);
        return -1;
    }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return -1;
    }

    *json_data = chunk.memory;

    curl_easy_cleanup(curl);
    return 0;
}

typedef struct
{
    char name[128];
    char version[20];
} Dependency;

typedef struct
{
    Dependency dependencies[MAX_DEPENDENCIES];
    int num_dependencies;
} DependencyList;

int read_dependencies(const char *json_filepath, DependencyList *dependency_list)
{
    FILE *file = fopen(json_filepath, "r");
    if (!file)
    {
        fprintf(stderr, "Failed to open %s for reading.\n", json_filepath);
        return 1;
    }

    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *data = (char *)malloc(length + 1);
    int64_t i;
    if ((i = fread(data, 1, length, file)) < length)
    {
        return 1;
    }

    fclose(file);
    data[length] = '\0';

    json_error_t error;
    json_t *root = json_loads(data, 0, &error);
    free(data);

    if (!root)
    {
        fprintf(stderr, "JSON parsing error: %s (line %d, column %d)\n", error.text, error.line, error.column);
        return 1;
    }

    json_t *dependencies = json_object_get(root, "dependencies");
    if (!json_is_object(dependencies))
    {
        fprintf(stderr, "Invalid JSON format: \"dependencies\" is not an object.\n");
        json_decref(root);
        return 1;
    }

    const char *name;
    json_t *version;
    int index = 0;
    json_object_foreach(dependencies, name, version)
    {
        if (index >= MAX_DEPENDENCIES)
        {
            fprintf(stderr, "Exceeded maximum number of dependencies.\n");
            break;
        }

        if (json_is_string(version))
        {
            strcpy(dependency_list->dependencies[index].name, name);
            strcpy(dependency_list->dependencies[index].version, json_string_value(version));
            index++;
        }
    }

    dependency_list->num_dependencies = index;

    json_decref(root);
    return 0;
}

typedef struct
{
    char lib_path[MAX_PATH_LENGTH];
    char cache_path[MAX_PATH_LENGTH];
    char server[MAX_PATH_LENGTH];
} Config;

int read_app_config(const char *json_filepath, Config *config)
{
    json_t *root;
    json_error_t error;

    // Open and parse the JSON file
    root = json_load_file(json_filepath, 0, &error);
    if (!root)
    {
        fprintf(stderr, "Error parsing JSON file: %s\n", error.text);
        return 1;
    }

    // Read packages_path from JSON
    json_t *packages_path_json = json_object_get(root, "packages_path");
    if (!json_is_string(packages_path_json))
    {
        fprintf(stderr, "Invalid JSON format: \"packages_path\" is not a string.\n");
        json_decref(root);
        return 1;
    }
    const char *packages_path = json_string_value(packages_path_json);
    if (strlen(packages_path) >= MAX_PATH_LENGTH)
    {
        fprintf(stderr, "packages_path exceeds maximum length.\n");
        json_decref(root);
        return 1;
    }
    strcpy(config->lib_path, packages_path);

    // Read cache_path from JSON
    json_t *cache_path_json = json_object_get(root, "cache_path");
    if (!json_is_string(cache_path_json))
    {
        fprintf(stderr, "Invalid JSON format: \"cache_path\" is not a string.\n");
        json_decref(root);
        return 1;
    }
    const char *cache_path_str = json_string_value(cache_path_json);
    if (strlen(cache_path_str) >= MAX_PATH_LENGTH)
    {
        fprintf(stderr, "cache_path exceeds maximum length.\n");
        json_decref(root);
        return 1;
    }
    strcpy(config->cache_path, cache_path_str);

    // Read server from JSON
    json_t *server_json = json_object_get(root, "server");
    if (!json_is_string(server_json))
    {
        fprintf(stderr, "Invalid JSON format: \"server\" is not a string.\n");
        json_decref(root);
        return 1;
    }
    const char *server_str = json_string_value(server_json);
    if (strlen(server_str) >= MAX_PATH_LENGTH)
    {
        fprintf(stderr, "server exceeds maximum length.\n");
        json_decref(root);
        return 1;
    }
    strcpy(config->server, server_str);

    // Cleanup JSON object
    json_decref(root);

    return 0;
}

int npi_update(Config *config, const char *arg)
{
    char pkg_name[128];
    char pkg_version[64];
    parse_input(arg, pkg_name, pkg_version);

    Package found_pkg;
    int result = check_package(config->lib_path, pkg_name, pkg_version, &found_pkg);
    if (result == 1)
    {
        if (strlen(pkg_version) == 0)
        {
            printf("Package %s found with version: ", pkg_name);
            print_package_version(&found_pkg);

            char url[MAX_PATH_LENGTH];
            construct_url(url, config->server, "packages", pkg_name, NULL);

            char *json_data = NULL;
            if (fetch_json_data(url, &json_data) == 0)
            {
                Package download_pkg;
                if (parse_downloaded_json(json_data, &download_pkg) < 0)
                {
                    free(json_data);
                    fprintf(stderr, "Failed to found package %s with version %s in repository.\n", pkg_name, pkg_version);
                    return -1;
                }
                free(json_data);

                if (compare_versions(&download_pkg.version, &found_pkg.version) > 0)
                {
                    char zip_filename[sizeof(download_pkg.name) +
                                      sizeof(download_pkg.version.major) +
                                      sizeof(download_pkg.version.minor) +
                                      sizeof(download_pkg.version.patch) +
                                      sizeof(download_pkg.version.prerelease) +
                                      sizeof(download_pkg.version.build) + 22];

                    if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                    {
                        snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d-%s+%s.zip",
                                 download_pkg.name,
                                 download_pkg.version.major,
                                 download_pkg.version.minor,
                                 download_pkg.version.patch,
                                 download_pkg.version.prerelease,
                                 download_pkg.version.build);
                    }
                    else
                    {
                        snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d.zip",
                                 download_pkg.name,
                                 download_pkg.version.major,
                                 download_pkg.version.minor,
                                 download_pkg.version.patch);
                    }

                    char zip_filepath[sizeof(zip_filename) + sizeof(config->cache_path) + 6];
                    snprintf(zip_filepath, sizeof(zip_filepath), "%s/%s", config->cache_path, zip_filename);

                    if (file_exists(zip_filepath))
                    {
                        printf("Using cached package %s with version %s.\n", pkg_name, pkg_version);
                    }
                    else
                    {
                        char version_str[sizeof(download_pkg.version.major) +
                                         sizeof(download_pkg.version.minor) +
                                         sizeof(download_pkg.version.patch) +
                                         sizeof(download_pkg.version.prerelease) +
                                         sizeof(download_pkg.version.build) + 22];

                        if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                        {
                            snprintf(version_str, sizeof(version_str), "%d.%d.%d-%s+%s",
                                     download_pkg.version.major,
                                     download_pkg.version.minor,
                                     download_pkg.version.patch,
                                     download_pkg.version.prerelease,
                                     download_pkg.version.build);
                        }
                        else
                        {
                            snprintf(version_str, sizeof(version_str), "%d.%d.%d",
                                     download_pkg.version.major,
                                     download_pkg.version.minor,
                                     download_pkg.version.patch);
                        }

                        construct_url(url, config->server, "download", download_pkg.name, version_str);
                        if (download_file(url, zip_filepath) == 0)
                        {
                            printf("Package %s with version %s downloaded.\n", download_pkg.name, version_str);
                        }
                        else
                        {
                            fprintf(stderr, "Failed to download package %s with version %s.\n", download_pkg.name, version_str);
                            return -1;
                        }
                    }
                    char unzip_filepath[sizeof(config->lib_path) + sizeof(download_pkg.name) + 6];
                    snprintf(unzip_filepath, sizeof(unzip_filepath), "%s/%s", config->lib_path, download_pkg.name);

                    remove_directory(unzip_filepath); // Remove the existing package directory
                    if (unzip_file(zip_filepath, unzip_filepath) < 0)
                    {
                        fprintf(stderr, "Failed to unpack package %s with version %s to %s.\n", pkg_name, pkg_version, unzip_filepath);
                        return -1;
                    } // Extract the new package
                    printf("Package %s with version %s installed.\n", pkg_name, pkg_version);

                    char json_filepath[sizeof(unzip_filepath) + strlen(PACKAGE_FILE) + 6];
                    snprintf(json_filepath, sizeof(json_filepath), "%s/%s", unzip_filepath, PACKAGE_FILE);

                    DependencyList dependency_list;
                    dependency_list.num_dependencies = 0;

                    int r = 0;
                    if (read_dependencies(json_filepath, &dependency_list) == 0)
                    {
                        if (dependency_list.num_dependencies > 0)
                            printf("Dependencies:\n");
                        for (int i = 0; i < dependency_list.num_dependencies; i++)
                        {
                            printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                            char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                            snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                            int t = npi_update(config, dependency_arg);
                            r = t > 0 ? r : t;
                        }
                    }
                    return r;
                }
            }
            else
            {
                fprintf(stderr, "Failed to fetch package metadata for %s with version %s.\n", pkg_name, pkg_version);
            }
        }
        else
        {
            printf("Package %s with version %s found.\n", pkg_name, pkg_version);
        }

        char json_filepath[sizeof(config->lib_path) + sizeof(pkg_name) + strlen(PACKAGE_FILE) + 2];
        snprintf(json_filepath, sizeof(json_filepath), "%s/%s/%s", config->lib_path, pkg_name, PACKAGE_FILE);

        DependencyList dependency_list;
        dependency_list.num_dependencies = 0;

        int r = 0;
        if (read_dependencies(json_filepath, &dependency_list) == 0)
        {
            if (dependency_list.num_dependencies > 0)
                printf("Dependencies:\n");
            for (int i = 0; i < dependency_list.num_dependencies; i++)
            {
                printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                int t = npi_update(config, dependency_arg);
                r = t > 0 ? r : t;
            }
        }
        return r;
    }
    else if (result == 2)
    {
        printf("Package %s found but version mismatch. Found version: ", pkg_name);
        print_package_version(&found_pkg);

        Version input_ver;
        parse_version(pkg_version, &input_ver);
        if (compare_versions(&input_ver, &found_pkg.version) > 0)
        {
            char url[MAX_PATH_LENGTH];
            construct_url(url, config->server, "packages", pkg_name, pkg_version);

            char *json_data = NULL;
            if (fetch_json_data(url, &json_data) == 0)
            {
                Package download_pkg;
                if (parse_downloaded_json(json_data, &download_pkg) < 0)
                {
                    free(json_data);
                    fprintf(stderr, "Failed to found package %s with version %s in repository.\n", pkg_name, pkg_version);
                    return -1;
                }
                free(json_data);

                char zip_filename[sizeof(download_pkg.name) +
                                  sizeof(download_pkg.version.major) +
                                  sizeof(download_pkg.version.minor) +
                                  sizeof(download_pkg.version.patch) +
                                  sizeof(download_pkg.version.prerelease) +
                                  sizeof(download_pkg.version.build) + 22];

                if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                {
                    snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d-%s+%s.zip",
                             download_pkg.name,
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch,
                             download_pkg.version.prerelease,
                             download_pkg.version.build);
                }
                else
                {
                    snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d.zip",
                             download_pkg.name,
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch);
                }

                char zip_filepath[sizeof(zip_filename) + sizeof(config->cache_path) + 6];
                snprintf(zip_filepath, sizeof(zip_filepath), "%s/%s", config->cache_path, zip_filename);

                if (file_exists(zip_filepath))
                {
                    printf("Using cached package %s with version %s.\n", pkg_name, pkg_version);
                }
                else
                {
                    char version_str[sizeof(download_pkg.version.major) +
                                     sizeof(download_pkg.version.minor) +
                                     sizeof(download_pkg.version.patch) +
                                     sizeof(download_pkg.version.prerelease) +
                                     sizeof(download_pkg.version.build) + 22];

                    if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                    {
                        snprintf(version_str, sizeof(version_str), "%d.%d.%d-%s+%s",
                                 download_pkg.version.major,
                                 download_pkg.version.minor,
                                 download_pkg.version.patch,
                                 download_pkg.version.prerelease,
                                 download_pkg.version.build);
                    }
                    else
                    {
                        snprintf(version_str, sizeof(version_str), "%d.%d.%d",
                                 download_pkg.version.major,
                                 download_pkg.version.minor,
                                 download_pkg.version.patch);
                    }

                    construct_url(url, config->server, "download", download_pkg.name, version_str);
                    if (download_file(url, zip_filepath) == 0)
                    {
                        printf("Package %s with version %s downloaded.\n", download_pkg.name, version_str);
                    }
                    else
                    {
                        fprintf(stderr, "Failed to download package %s with version %s.\n", download_pkg.name, version_str);
                        return -1;
                    }
                }
                char unzip_filepath[sizeof(config->lib_path) + sizeof(download_pkg.name) + 6];
                snprintf(unzip_filepath, sizeof(unzip_filepath), "%s/%s", config->lib_path, download_pkg.name);

                remove_directory(unzip_filepath); // Remove the existing package directory
                if (unzip_file(zip_filepath, unzip_filepath) < 0)
                {
                    fprintf(stderr, "Failed to unpack package %s with version %s to %s.\n", pkg_name, pkg_version, unzip_filepath);
                    return -1;
                } // Extract the new package
                printf("Package %s with version %s installed.\n", pkg_name, pkg_version);

                char json_filepath[sizeof(unzip_filepath) + strlen(PACKAGE_FILE) + 6];
                snprintf(json_filepath, sizeof(json_filepath), "%s/%s", unzip_filepath, PACKAGE_FILE);

                DependencyList dependency_list;
                dependency_list.num_dependencies = 0;

                int r = 0;
                if (read_dependencies(json_filepath, &dependency_list) == 0)
                {
                    if (dependency_list.num_dependencies > 0)
                        printf("Dependencies:\n");
                    for (int i = 0; i < dependency_list.num_dependencies; i++)
                    {
                        printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                        char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                        snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                        int t = npi_update(config, dependency_arg);
                        r = t > 0 ? r : t;
                    }
                }
                return r;
            }
            else
            {
                fprintf(stderr, "Failed to fetch package metadata for %s with version %s.\n", pkg_name, pkg_version);
            }
        }
    }
    else
    {
        char url[MAX_PATH_LENGTH];
        construct_url(url, config->server, "packages", pkg_name, pkg_version);

        char *json_data = NULL;
        if (fetch_json_data(url, &json_data) == 0)
        {
            Package download_pkg;
            if (parse_downloaded_json(json_data, &download_pkg) < 0)
            {
                free(json_data);
                fprintf(stderr, "Failed to found package %s in repository.\n", pkg_name);
                return -1;
            }
            free(json_data);

            char zip_filename[sizeof(download_pkg.name) +
                              sizeof(download_pkg.version.major) +
                              sizeof(download_pkg.version.minor) +
                              sizeof(download_pkg.version.patch) +
                              sizeof(download_pkg.version.prerelease) +
                              sizeof(download_pkg.version.build) + 22];

            if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
            {
                snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d-%s+%s.zip",
                         download_pkg.name,
                         download_pkg.version.major,
                         download_pkg.version.minor,
                         download_pkg.version.patch,
                         download_pkg.version.prerelease,
                         download_pkg.version.build);
            }
            else
            {
                snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d.zip",
                         download_pkg.name,
                         download_pkg.version.major,
                         download_pkg.version.minor,
                         download_pkg.version.patch);
            }

            char zip_filepath[sizeof(zip_filename) + sizeof(config->cache_path) + 6];
            snprintf(zip_filepath, sizeof(zip_filepath), "%s/%s", config->cache_path, zip_filename);

            if (file_exists(zip_filepath))
            {
                printf("Using cached package %s.\n", pkg_name);
            }
            else
            {
                char version_str[sizeof(download_pkg.version.major) +
                                 sizeof(download_pkg.version.minor) +
                                 sizeof(download_pkg.version.patch) +
                                 sizeof(download_pkg.version.prerelease) +
                                 sizeof(download_pkg.version.build) + 22];

                if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                {
                    snprintf(version_str, sizeof(version_str), "%d.%d.%d-%s+%s",
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch,
                             download_pkg.version.prerelease,
                             download_pkg.version.build);
                }
                else
                {
                    snprintf(version_str, sizeof(version_str), "%d.%d.%d",
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch);
                }

                construct_url(url, config->server, "download", download_pkg.name, version_str);
                if (download_file(url, zip_filepath) == 0)
                {
                    printf("Package %s with version %s downloaded.\n", download_pkg.name, version_str);
                }
                else
                {
                    fprintf(stderr, "Failed to download package %s with version %s.\n", download_pkg.name, version_str);
                    return -1;
                }
            }

            char unzip_filepath[sizeof(config->lib_path) + sizeof(download_pkg.name) + 6];
            snprintf(unzip_filepath, sizeof(unzip_filepath), "%s/%s", config->lib_path, download_pkg.name);

            remove_directory(unzip_filepath); // Remove the existing package directory
            if (unzip_file(zip_filepath, unzip_filepath) < 0)
            {
                fprintf(stderr, "Failed to unpack package %s to %s.\n", pkg_name, unzip_filepath);
                return 1;
            } // Extract the new package

            printf("Package %s installed.\n", pkg_name);

            char json_filepath[sizeof(unzip_filepath) + strlen(PACKAGE_FILE) + 6];
            snprintf(json_filepath, sizeof(json_filepath), "%s/%s", unzip_filepath, PACKAGE_FILE);

            DependencyList dependency_list;
            dependency_list.num_dependencies = 0;

            int r = 0;
            if (read_dependencies(json_filepath, &dependency_list) == 0)
            {
                if (dependency_list.num_dependencies > 0)
                    printf("Dependencies:\n");
                for (int i = 0; i < dependency_list.num_dependencies; i++)
                {
                    printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                    char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                    snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                    int t = npi_update(config, dependency_arg);
                    r = t > 0 ? r : t;
                }
            }
            return r;
        }
        else
        {
            fprintf(stderr, "Failed to fetch package metadata for %s.\n", pkg_name);
        }
    }

    return 0;
}

int npi_install(Config *config, const char *arg)
{
    char pkg_name[128];
    char pkg_version[64];
    parse_input(arg, pkg_name, pkg_version);

    Package found_pkg;
    int result = check_package(config->lib_path, pkg_name, pkg_version, &found_pkg);
    if (result == 1)
    {
        if (strlen(pkg_version) == 0)
        {
            printf("Package %s found with version: ", pkg_name);
            print_package_version(&found_pkg);
        }
        else
        {
            printf("Package %s with version %s found.\n", pkg_name, pkg_version);
        }

        char json_filepath[sizeof(config->lib_path) + sizeof(pkg_name) + strlen(PACKAGE_FILE) + 2];
        snprintf(json_filepath, sizeof(json_filepath), "%s/%s/%s", config->lib_path, pkg_name, PACKAGE_FILE);

        DependencyList dependency_list;
        dependency_list.num_dependencies = 0;

        int r = 0;
        if (read_dependencies(json_filepath, &dependency_list) == 0)
        {
            if (dependency_list.num_dependencies > 0)
                printf("Dependencies:\n");
            for (int i = 0; i < dependency_list.num_dependencies; i++)
            {
                printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                int t = npi_update(config, dependency_arg);
                r = t > 0 ? r : t;
            }
        }
        return r;
    }
    else if (result == 2)
    {
        printf("Package %s found but version mismatch. Found version: ", pkg_name);
        print_package_version(&found_pkg);

        char url[MAX_PATH_LENGTH];
        construct_url(url, config->server, "packages", pkg_name, pkg_version);

        char *json_data = NULL;
        if (fetch_json_data(url, &json_data) == 0)
        {
            Package download_pkg;
            if (parse_downloaded_json(json_data, &download_pkg) < 0)
            {
                free(json_data);
                fprintf(stderr, "Failed to found package %s with version %s in repository.\n", pkg_name, pkg_version);
                return -1;
            }
            free(json_data);

            char zip_filename[sizeof(download_pkg.name) +
                              sizeof(download_pkg.version.major) +
                              sizeof(download_pkg.version.minor) +
                              sizeof(download_pkg.version.patch) +
                              sizeof(download_pkg.version.prerelease) +
                              sizeof(download_pkg.version.build) + 22];

            if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
            {
                snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d-%s+%s.zip",
                         download_pkg.name,
                         download_pkg.version.major,
                         download_pkg.version.minor,
                         download_pkg.version.patch,
                         download_pkg.version.prerelease,
                         download_pkg.version.build);
            }
            else
            {
                snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d.zip",
                         download_pkg.name,
                         download_pkg.version.major,
                         download_pkg.version.minor,
                         download_pkg.version.patch);
            }

            char zip_filepath[sizeof(zip_filename) + sizeof(config->cache_path) + 6];
            snprintf(zip_filepath, sizeof(zip_filepath), "%s/%s", config->cache_path, zip_filename);

            if (file_exists(zip_filepath))
            {
                printf("Using cached package %s with version %s.\n", pkg_name, pkg_version);
            }
            else
            {
                char version_str[sizeof(download_pkg.version.major) +
                                 sizeof(download_pkg.version.minor) +
                                 sizeof(download_pkg.version.patch) +
                                 sizeof(download_pkg.version.prerelease) +
                                 sizeof(download_pkg.version.build) + 22];

                if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                {
                    snprintf(version_str, sizeof(version_str), "%d.%d.%d-%s+%s",
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch,
                             download_pkg.version.prerelease,
                             download_pkg.version.build);
                }
                else
                {
                    snprintf(version_str, sizeof(version_str), "%d.%d.%d",
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch);
                }

                construct_url(url, config->server, "download", download_pkg.name, version_str);
                if (download_file(url, zip_filepath) == 0)
                {
                    printf("Package %s with version %s downloaded.\n", download_pkg.name, version_str);
                }
                else
                {
                    fprintf(stderr, "Failed to download package %s with version %s.\n", download_pkg.name, version_str);
                    return -1;
                }
            }

            char unzip_filepath[sizeof(config->lib_path) + sizeof(download_pkg.name) + 6];
            snprintf(unzip_filepath, sizeof(unzip_filepath), "%s/%s", config->lib_path, download_pkg.name);

            remove_directory(unzip_filepath); // Remove the existing package directory
            if (unzip_file(zip_filepath, unzip_filepath) < 0)
            {
                fprintf(stderr, "Failed to unpack package %s with version %s to %s.\n", pkg_name, pkg_version, unzip_filepath);
                return -1;
            } // Extract the new package
            printf("Package %s with version %s installed.\n", pkg_name, pkg_version);

            char json_filepath[sizeof(unzip_filepath) + strlen(PACKAGE_FILE) + 6];
            snprintf(json_filepath, sizeof(json_filepath), "%s/%s", unzip_filepath, PACKAGE_FILE);

            DependencyList dependency_list;
            dependency_list.num_dependencies = 0;

            int r = 0;
            if (read_dependencies(json_filepath, &dependency_list) == 0)
            {
                if (dependency_list.num_dependencies > 0)
                    printf("Dependencies:\n");
                for (int i = 0; i < dependency_list.num_dependencies; i++)
                {
                    printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                    char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                    snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                    int t = npi_update(config, dependency_arg);
                    r = t > 0 ? r : t;
                }
            }
            return r;
        }
        else
        {
            fprintf(stderr, "Failed to fetch package metadata for %s with version %s.\n", pkg_name, pkg_version);
        }
    }
    else
    {
        char url[MAX_PATH_LENGTH];
        construct_url(url, config->server, "packages", pkg_name, pkg_version);

        char *json_data = NULL;
        if (fetch_json_data(url, &json_data) == 0)
        {
            Package download_pkg;
            if (parse_downloaded_json(json_data, &download_pkg) < 0)
            {
                free(json_data);
                fprintf(stderr, "Failed to found package %s in repository.\n", pkg_name);
                return -1;
            }
            free(json_data);

            char zip_filename[sizeof(download_pkg.name) +
                              sizeof(download_pkg.version.major) +
                              sizeof(download_pkg.version.minor) +
                              sizeof(download_pkg.version.patch) +
                              sizeof(download_pkg.version.prerelease) +
                              sizeof(download_pkg.version.build) + 22];

            if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
            {
                snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d-%s+%s.zip",
                         download_pkg.name,
                         download_pkg.version.major,
                         download_pkg.version.minor,
                         download_pkg.version.patch,
                         download_pkg.version.prerelease,
                         download_pkg.version.build);
            }
            else
            {
                snprintf(zip_filename, sizeof(zip_filename), "%s-%d.%d.%d.zip",
                         download_pkg.name,
                         download_pkg.version.major,
                         download_pkg.version.minor,
                         download_pkg.version.patch);
            }

            char zip_filepath[sizeof(zip_filename) + sizeof(config->cache_path) + 6];
            snprintf(zip_filepath, sizeof(zip_filepath), "%s/%s", config->cache_path, zip_filename);

            if (file_exists(zip_filepath))
            {
                printf("Using cached package %s.\n", pkg_name);
            }
            else
            {
                char version_str[sizeof(download_pkg.version.major) +
                                 sizeof(download_pkg.version.minor) +
                                 sizeof(download_pkg.version.patch) +
                                 sizeof(download_pkg.version.prerelease) +
                                 sizeof(download_pkg.version.build) + 22];

                if ((strlen(download_pkg.version.prerelease) > 0) && (strlen(download_pkg.version.build) > 0))
                {
                    snprintf(version_str, sizeof(version_str), "%d.%d.%d-%s+%s",
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch,
                             download_pkg.version.prerelease,
                             download_pkg.version.build);
                }
                else
                {
                    snprintf(version_str, sizeof(version_str), "%d.%d.%d",
                             download_pkg.version.major,
                             download_pkg.version.minor,
                             download_pkg.version.patch);
                }

                construct_url(url, config->server, "download", download_pkg.name, version_str);
                if (download_file(url, zip_filepath) == 0)
                {
                    printf("Package %s with version %s downloaded.\n", download_pkg.name, version_str);
                }
                else
                {
                    fprintf(stderr, "Failed to download package %s with version %s.\n", download_pkg.name, version_str);
                    return -1;
                }
            }

            char unzip_filepath[sizeof(config->lib_path) + sizeof(download_pkg.name) + 6];
            snprintf(unzip_filepath, sizeof(unzip_filepath), "%s/%s", config->lib_path, download_pkg.name);

            remove_directory(unzip_filepath); // Remove the existing package directory
            if (unzip_file(zip_filepath, unzip_filepath) < 0)
            {
                fprintf(stderr, "Failed to unpack package %s to %s.\n", pkg_name, unzip_filepath);
                return 1;
            } // Extract the new package

            printf("Package %s installed.\n", pkg_name);

            char json_filepath[sizeof(unzip_filepath) + strlen(PACKAGE_FILE) + 6];
            snprintf(json_filepath, sizeof(json_filepath), "%s/%s", unzip_filepath, PACKAGE_FILE);

            DependencyList dependency_list;
            dependency_list.num_dependencies = 0;

            int r = 0;
            if (read_dependencies(json_filepath, &dependency_list) == 0)
            {
                if (dependency_list.num_dependencies > 0)
                    printf("Dependencies:\n");
                for (int i = 0; i < dependency_list.num_dependencies; i++)
                {
                    printf("%s=%s\n", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                    char dependency_arg[sizeof(dependency_list.dependencies[i].name) + sizeof(dependency_list.dependencies[i].version) + 1];
                    snprintf(dependency_arg, sizeof(dependency_arg), "%s=%s", dependency_list.dependencies[i].name, dependency_list.dependencies[i].version);

                    int t = npi_update(config, dependency_arg);
                    r = t > 0 ? r : t;
                }
            }
            return r;
        }
        else
        {
            fprintf(stderr, "Failed to fetch package metadata for %s.\n", pkg_name);
        }
    }

    return 0;
}

int npi_remove(Config *config, const char *arg)
{
    char pkg_name[128];
    char pkg_version[64];
    parse_input(arg, pkg_name, pkg_version);

    Package found_pkg;
    int result = check_package(config->lib_path, pkg_name, pkg_version, &found_pkg);
    if (result == 1)
    {
        if (strlen(pkg_version) == 0)
        {
            printf("Package %s found with version: ", pkg_name);
            print_package_version(&found_pkg);
        }
        else
        {
            printf("Package %s with version %s found.\n", pkg_name, pkg_version);
        }

        char unzip_filepath[sizeof(config->lib_path) + sizeof(pkg_name) + 6];
        snprintf(unzip_filepath, sizeof(unzip_filepath), "%s/%s", config->lib_path, pkg_name);

        remove_directory(unzip_filepath);

        if (strlen(pkg_version) == 0)
        {
            printf("Package %s removed.\n", pkg_name);
        }
        else
        {
            printf("Package %s with version %s removed.\n", pkg_name, pkg_version);
        }
    }
    else if (result == 2)
    {
        printf("Package %s found but version mismatch. Found version: ", pkg_name);
        print_package_version(&found_pkg);
        return -1;
    }
    else
    {
        if (strlen(pkg_version) == 0)
        {
            printf("Package %s not found.\n", pkg_name);
        }
        else
        {
            printf("Package %s with version %s not found.\n", pkg_name, pkg_version);
        }
        return -1;
    }

    return 0;
}

int npi_help(const char *filename)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
    {
        perror("Error opening file help.txt");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file))
    {
        printf("%s", line);
    }

    fclose(file);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <option> <package_name>[=<version>]\n", argv[0]);
        return -1;
    }

    Config config;

    if (read_app_config(CONFIG_FILE, &config) != 0)
    {
        fprintf(stderr, "Failed to read app config.\n");
        return 1;
    }

    long i;
    for (i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-i") == 0) || (strcmp(argv[i], "-install") == 0))
        {
            i += 1;
            for (; i < argc; i++)
            {
                if (npi_install(&config, argv[i]) < 0)
                {
                    return -1;
                }
            }
            break;
        }
        else if ((strcmp(argv[i], "-r") == 0) || (strcmp(argv[i], "-remove") == 0))
        {
            i += 1;
            for (; i < argc; i++)
            {
                if (npi_remove(&config, argv[i]) < 0)
                {
                    return -1;
                }
            }
            break;
        }
        else if ((strcmp(argv[i], "-u") == 0) || (strcmp(argv[i], "-update") == 0))
        {
            i += 1;
            for (; i < argc; i++)
            {
                if (npi_update(&config, argv[i]) < 0)
                {
                    return -1;
                }
            }
            break;
        }
        else if ((strcmp(argv[i], "-h") == 0))
        {
            if (npi_help("help.txt") < 0)
            {
                return -1;
            }
            break;
        }
    }

    return 0;
}