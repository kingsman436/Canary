#include <iostream>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>

namespace fs = std::filesystem;
using json = nlohmann::json;

bool compareCVEWithPackageJSON(const json& cveData, const json& packageJsonData, std::ofstream& outputFile) {
    try {
        // Check if required keys exist in CVE data
        if (cveData.contains("containers") && cveData["containers"].contains("cna") &&
            cveData["containers"]["cna"].contains("affected") &&
            cveData["containers"]["cna"]["affected"].is_array() &&
            !cveData["containers"]["cna"]["affected"].empty()) {

            // Extract product name and version from CVE data
            std::vector<std::pair<std::string, std::string>> affectedProducts;
            for (const auto& affected : cveData["containers"]["cna"]["affected"]) {
                std::string productName = affected.value("product", "n/a");
                std::string productVersion = affected["versions"][0].value("version", "n/a");
                affectedProducts.emplace_back(productName, productVersion);
            }

            // Compare product name and version with each dependency in package.json
            for (const auto& dependency : packageJsonData["dependencies"].items()) {
                std::string dependencyName = dependency.key();
                std::string dependencyVersion = dependency.value();

                // Compare product name and version with each affected product in CVE data
                for (const auto& affectedProduct : affectedProducts) {
                    if (dependencyName == affectedProduct.first && dependencyVersion == affectedProduct.second) {
                        outputFile << "Found vulnerability in dependency: " << dependencyName << " (version: " << dependencyVersion << ")" << std::endl;
                        return true; // Found common information
                    }
                }
            }
        }
        else {
            std::cerr << "CVE data does not have the expected structure." << std::endl;
        }
    }
    catch (const std::exception& e) {
        std::cerr << "Error comparing CVE data with package.json: " << e.what() << std::endl;
    }

    return false; // No common information found or invalid CVE data structure
}

void processJsonFile(const std::string& filePath, const json& packageJsonData, std::ofstream& outputFile) {
    std::ifstream jsonFile(filePath);

    // Check if the file is open
    if (!jsonFile.is_open()) {
        std::cerr << "Error opening the file: " << filePath << std::endl;
        return;
    }

    try {
        // Parse the JSON data
        json jsonData = json::parse(jsonFile);

        // Close the file
        jsonFile.close();

        // Print success message for each file
        outputFile << "JSON file successfully read and parsed: " << filePath << std::endl;

        // Compare CVE data with package.json data
        if (compareCVEWithPackageJSON(jsonData, packageJsonData, outputFile)) {
            outputFile << "Found common information between CVE and package.json in file: " << filePath << std::endl;
        }
    }
    catch (const json::parse_error& e) {
        outputFile << "JSON parsing error in file " << filePath << ": " << e.what() << std::endl;
    }
    catch (const json::exception& e) {
        outputFile << "JSON exception occurred while processing JSON file " << filePath << ": " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        outputFile << "An error occurred while processing JSON file " << filePath << ": " << e.what() << std::endl;
    }
}

int main() {
    // Specify the directory containing the JSON files
    std::string directoryPath = "C:\\Users\\Justin L\\source\\repos\\cvelistV5\\cves\\2024";

    // Read and parse package.json
    std::string packageJsonPath = "package.json";
    json packageJsonData;
    {
        std::ifstream packageJsonFile(packageJsonPath);
        if (!packageJsonFile.is_open()) {
            std::cerr << "Error opening the file: " << packageJsonPath << std::endl;
            return 1;
        }

        try {
            // Parse the JSON data
            packageJsonFile >> packageJsonData;
        }
        catch (const json::parse_error& e) {
            std::cerr << "JSON parsing error in file " << packageJsonPath << ": " << e.what() << std::endl;
            return 1;
        }

        // Close the file
        packageJsonFile.close();
    }

    // Open output file
    std::ofstream outputFile("output.txt");
    if (!outputFile.is_open()) {
        std::cerr << "Error opening output file." << std::endl;
        return 1;
    }

    // Iterate over files in the directory and its subdirectories
    for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
        if (entry.is_regular_file() && entry.path().extension() == ".json") {
            // Process each JSON file
            processJsonFile(entry.path().string(), packageJsonData, outputFile);
        }
    }

    // Close output file
    outputFile.close();

    return 0;
}
