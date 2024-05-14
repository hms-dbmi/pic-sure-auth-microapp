package edu.harvard.hms.dbmi.avillach.auth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;

public class FenceMapping {

    @JsonProperty("bio_data_catalyst")
    private ArrayList<ProjectMetaData> bio_data_catalyst;

    public ArrayList<ProjectMetaData> getBio_data_catalyst() {
        return bio_data_catalyst;
    }

    public void setBio_data_catalyst(ArrayList<ProjectMetaData> bio_data_catalyst) {
        this.bio_data_catalyst = bio_data_catalyst;
    }
}
