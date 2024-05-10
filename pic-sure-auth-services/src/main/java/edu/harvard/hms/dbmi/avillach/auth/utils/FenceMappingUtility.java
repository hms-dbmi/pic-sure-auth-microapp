package edu.harvard.hms.dbmi.avillach.auth.utils;

import edu.harvard.hms.dbmi.avillach.auth.JAXRSConfiguration;
import edu.harvard.hms.dbmi.avillach.auth.model.BioDataCatalyst;
import edu.harvard.hms.dbmi.avillach.auth.model.FenceMapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.ejb.DependsOn;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import java.io.File;
import java.io.IOException;
import java.util.*;

@Singleton
@Startup
@DependsOn("JAXRSConfiguration")
public class FenceMappingUtility {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private Map<String, BioDataCatalyst> _projectMap;
    private Map<String, BioDataCatalyst> fenceMappingByAuthZ;

    @PostConstruct
    public void init() {
        try {
            initializeFENCEMapping();
            initializeFenceMappingByAuthZ();
        } catch (IOException e) {
            logger.error("Error initializing FENCE mappings", e);
        }
    }

    private void initializeFENCEMapping() throws IOException {
        ArrayList<BioDataCatalyst> projects = loadBioDataCatalystFenceMappingData();
        _projectMap = new HashMap<>(projects.size());
        for (BioDataCatalyst project : projects) {
            String consentVal = (project.getConsent_group_code() != null && !project.getConsent_group_code().isEmpty()) ?
                    project.getStudy_identifier() + "." + project.getConsent_group_code() :
                    project.getStudy_identifier();
            _projectMap.put(consentVal, project);
        }
    }

    private void initializeFenceMappingByAuthZ() throws IOException {
        ArrayList<BioDataCatalyst> projects = loadBioDataCatalystFenceMappingData();
        fenceMappingByAuthZ = new HashMap<>(projects.size());
        for (BioDataCatalyst project : projects) {
            fenceMappingByAuthZ.put(project.getAuthZ().replace("\\/", "/"), project);
        }
    }

    public Map<String, BioDataCatalyst> getFENCEMapping() {
        return _projectMap;
    }

    public Map<String, BioDataCatalyst> getFenceMappingByAuthZ() {
        return fenceMappingByAuthZ;
    }

    private ArrayList<BioDataCatalyst> loadBioDataCatalystFenceMappingData() {
        FenceMapping fenceMapping;
        ArrayList<BioDataCatalyst> projects;
        try {
            fenceMapping = JAXRSConfiguration.objectMapper.readValue(
                    new File(String.join(File.separator,
                            new String[] {JAXRSConfiguration.templatePath ,"fence_mapping.json"}))
                    , FenceMapping.class);

            projects = fenceMapping.getProjectMetaData();
            logger.debug("getFENCEMapping: found FENCE mapping with {} entries", projects.size());
        } catch (Exception e) {
            logger.error("loadFenceMappingData: Non-fatal error parsing fence_mapping.json: {}", JAXRSConfiguration.templatePath, e);
            return new ArrayList<>();
        }
        return projects;
    }

}
