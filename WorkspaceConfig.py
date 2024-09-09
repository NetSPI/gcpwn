import json
from UtilityController import UtilityTools

class WorkspaceConfig:
    ALLOWED_OUTPUT_FORMATS = {"table", "csv", "txt"}
    
    # Default table, user can change to txt/csv
    def __init__(self, json_data=None):
        # Initialize class variables with default values
        self.preferred_output_formats = ["table"]
        self.preferred_project_ids = None
        self.preferred_regions = None
        self.preferred_zones = None
        
        # If JSON data is provided, populate the class variables
        if json_data:
            self.from_json(json_data)

    def from_json(self, json_data):
        """Populate the class variables from JSON data."""
        data = json.loads(json_data)
        
        try:
            # Update the class attributes if they are present in the JSON data
            if 'preferred_output_formats' in data:
                if data['preferred_output_formats'] == None:
                    data['preferred_output_formats'] = ["table"]
                self.set_preferred_output_formats(data['preferred_output_formats'])
        except Exception as e:
                self.preferred_output_formats = "table"

        if 'preferred_project_ids' in data:
            self.preferred_project_ids = data['preferred_project_ids']
        if 'preferred_regions' in data:
            self.preferred_regions = data['preferred_regions']
        if 'preferred_zones' in data:
            self.preferred_zones = data['preferred_zones']

    def to_json_string(self):
        """Serialize the current object state to a JSON string."""
        data = {
            'preferred_output_formats': self.preferred_output_formats,
            'preferred_project_ids': self.preferred_project_ids,
            'preferred_regions': self.preferred_regions,
            'preferred_zones': self.preferred_zones,
        }
        return json.dumps(data)

    def print_json_formatted(self):
        data = json.loads(self.to_json_string())
        max_key_length = max(len(key) for key in data.keys())
        
        for key, value in data.items():
            # Right-align the key and format with padding
            key_str = f"{key.rjust(max_key_length)}:"

            # Format the value
            if value is None:
                value_str = f"{UtilityTools.RED}[Not Set]{UtilityTools.RESET}"
            else:
                value_str = f"{UtilityTools.GREEN}"+str(value)+f"{UtilityTools.RESET}"

            # Print the formatted key-value pair
            print(f"{UtilityTools.BOLD}{key_str}{UtilityTools.RESET} {value_str}")

    # Getter and Setter for preferred_output_formats
    def get_preferred_output_formats(self):
        return self.preferred_output_formats

    def set_preferred_output_formats(self, value):
        if isinstance(value, list):
            validated_formats = [self._validate_output_format(v) for v in value]
            self.preferred_output_formats = validated_formats
        else:
            raise ValueError("preferred_output_formats must be a list of strings.")

    def _validate_output_format(self, value):
        value_lower = value.lower()
        if value_lower not in self.ALLOWED_OUTPUT_FORMATS:
            raise ValueError(f"Invalid value '{value}'. Allowed values are: {', '.join(self.ALLOWED_OUTPUT_FORMATS)}.")
        return value_lower

    # Getter and Setter for preferred_project_ids
    def get_preferred_project_ids(self):
        return self.preferred_project_ids

    def set_preferred_project_ids(self, value):
        self.preferred_project_ids = value

    # Getter and Setter for preferred_regions
    def get_preferred_regions(self):
        return self.preferred_regions

    def set_preferred_regions(self, value):
        self.preferred_regions = value

    # Getter and Setter for preferred_zones
    def get_preferred_zones(self):
        return self.preferred_zones

    def set_preferred_zones(self, value):
        self.preferred_zones = value
