package edu.harvard.hms.dbmi.avillach.auth.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import edu.harvard.hms.dbmi.avillach.auth.model.StudyMetaData;
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
    private Map<String, StudyMetaData> fenceMappingByConsent;
    private Map<String, StudyMetaData> fenceMappingByAuthZ;
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
        ArrayList<StudyMetaData> studies = loadBioDataCatalystFenceMappingData();
        fenceMappingByConsent = new HashMap<>(studies.size());
        for (StudyMetaData study : studies) {
            String consentVal = (study.getConsent_group_code() != null && !study.getConsent_group_code().isEmpty()) ?
                    study.getStudy_identifier() + "." + study.getConsent_group_code() :
                    study.getStudy_identifier();
            fenceMappingByConsent.put(consentVal, study);
        }
    }

    private void initializeFenceMappingByAuthZ() throws IOException {
        ArrayList<StudyMetaData> studies = loadBioDataCatalystFenceMappingData();
        fenceMappingByAuthZ = new HashMap<>(studies.size());
        for (StudyMetaData study : studies) {
            fenceMappingByAuthZ.put(study.getAuthZ().replace("\\/", "/"), study);
        }
    }

    public Map<String, StudyMetaData> getFENCEMapping() {
        return fenceMappingByConsent;
    }

    public Map<String, StudyMetaData> getFenceMappingByAuthZ() {
        return fenceMappingByAuthZ;
    }

    private ArrayList<StudyMetaData> loadBioDataCatalystFenceMappingData() {
        FenceMapping fenceMapping;
        ArrayList<StudyMetaData> studies;
        try {
            logger.debug("getFENCEMapping: loading FENCE mapping from {}", templatePath);
            fenceMapping = objectMapper.readValue(
                    new File(String.join(File.separator,
                            new String[]{templatePath, "fence_mapping.json"}))
                    , FenceMapping.class);

            studies = fenceMapping.getBio_data_catalyst();
            logger.debug("getFENCEMapping: found FENCE mapping with {} entries", studies.size());
        } catch (Exception e) {
            logger.error("loadFenceMappingData: Non-fatal error parsing fence_mapping.json: {}", templatePath, e);
            return new ArrayList<>();
        }
        return studies;
    }

}
