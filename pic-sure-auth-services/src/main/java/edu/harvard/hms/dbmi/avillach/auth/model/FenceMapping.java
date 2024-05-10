package edu.harvard.hms.dbmi.avillach.auth.model;

import java.util.ArrayList;

public class FenceMapping {

    private ArrayList<BioDataCatalyst> projectMetaData;

    public ArrayList<BioDataCatalyst> getProjectMetaData() {
        return projectMetaData;
    }

    public void setProjectMetaData(ArrayList<BioDataCatalyst> projectMetaData) {
        this.projectMetaData = projectMetaData;
    }
}
