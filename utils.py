import json
import configparser


def get_json_file(filename):
    with open(filename) as json_file:
        data = json.load(json_file)
    return data


def get_config_file(filename):
    config = configparser.ConfigParser()
    config.optionxform = str  # Keep up case values as suck instead of having everything as lowercase
    config.read(filename)
    return config


def get_config_file_section(filename, section):
    config = get_config_file(filename)
    if section in config.sections():
        return config[section]


def write_config_to_file(filename, config_dict):
    config = configparser.ConfigParser(config_dict)
    with open(filename, 'w') as configfile:
        config.write(configfile)


def get_file(filename):
    split_filename = filename.split('.')
    file_extension = split_filename[-1]
    if file_extension == 'json':
        return get_json_file(filename)
    elif file_extension == 'ini':
        return get_config_file(filename)
    else:
        raise UnknownFileExtension


class UnknownFileExtension(Exception):
    """
    Raised when the file extension we are trying to read is unknown/not supported
    """
