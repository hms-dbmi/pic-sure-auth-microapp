package edu.harvard.hms.dbmi.avillach.auth.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.model.ProjectMetaData;
import edu.harvard.hms.dbmi.avillach.auth.model.FenceMapping;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import java.io.File;
import java.io.IOException;
import java.util.*;

@Singleton
@Startup
public class FenceMappingUtility {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());
    private Map<String, ProjectMetaData> _projectMap;
    private Map<String, ProjectMetaData> fenceMappingByAuthZ;
    private static String templatePath;
    private ObjectMapper objectMapper;

    @PostConstruct
    public void init() {
        try {
            Context ctx = new InitialContext();
            templatePath = (String) ctx.lookup("java:global/templatePath");
            objectMapper = new ObjectMapper();

            initializeFENCEMapping();
            initializeFenceMappingByAuthZ();
        } catch (IOException e) {
            logger.error("Error initializing FENCE mappings", e);
        } catch (NamingException e) {
            throw new RuntimeException(e);
        }
    }

    private void initializeFENCEMapping() throws IOException {
        ArrayList<ProjectMetaData> projects = loadBioDataCatalystFenceMappingData();
        _projectMap = new HashMap<>(projects.size());
        for (ProjectMetaData project : projects) {
            String consentVal = (project.getConsent_group_code() != null && !project.getConsent_group_code().isEmpty()) ?
                    project.getStudy_identifier() + "." + project.getConsent_group_code() :
                    project.getStudy_identifier();
            _projectMap.put(consentVal, project);
        }
    }

    private void initializeFenceMappingByAuthZ() throws IOException {
        ArrayList<ProjectMetaData> projects = loadBioDataCatalystFenceMappingData();
        fenceMappingByAuthZ = new HashMap<>(projects.size());
        for (ProjectMetaData project : projects) {
            fenceMappingByAuthZ.put(project.getAuthZ().replace("\\/", "/"), project);
        }
    }

    public Map<String, ProjectMetaData> getFENCEMapping() {
        return _projectMap;
    }

    public Map<String, ProjectMetaData> getFenceMappingByAuthZ() {
        return fenceMappingByAuthZ;
    }

    private ArrayList<ProjectMetaData> loadBioDataCatalystFenceMappingData() {
        FenceMapping fenceMapping;
        ArrayList<ProjectMetaData> projects;
        try {
            logger.debug("getFENCEMapping: loading FENCE mapping from {}", templatePath);
            fenceMapping = objectMapper.readValue(
                    new File(String.join(File.separator,
                            new String[]{templatePath, "fence_mapping.json"}))
                    , FenceMapping.class);

            projects = fenceMapping.getBio_data_catalyst();
            logger.debug("getFENCEMapping: found FENCE mapping with {} entries", projects.size());
        } catch (Exception e) {
            logger.error("loadFenceMappingData: Non-fatal error parsing fence_mapping.json: {}", templatePath, e);
            return new ArrayList<>();
        }
        return projects;
    }

}
