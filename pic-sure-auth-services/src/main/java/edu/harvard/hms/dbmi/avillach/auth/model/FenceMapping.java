package edu.harvard.hms.dbmi.avillach.auth.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;

public class FenceMapping {

    @JsonProperty("bio_data_catalyst")
    private ArrayList<StudyMetaData> bio_data_catalyst;

    public ArrayList<StudyMetaData> getBio_data_catalyst() {
        return bio_data_catalyst;
    }

    public void setBio_data_catalyst(ArrayList<StudyMetaData> bio_data_catalyst) {
        this.bio_data_catalyst = bio_data_catalyst;
    }
}
