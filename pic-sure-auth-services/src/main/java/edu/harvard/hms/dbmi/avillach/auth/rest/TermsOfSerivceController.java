package edu.harvard.hms.dbmi.avillach.auth.rest;

import edu.harvard.hms.dbmi.avillach.auth.model.response.PICSUREResponse;
import edu.harvard.hms.dbmi.avillach.auth.service.impl.TOSService;
import edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import jakarta.annotation.security.RolesAllowed;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import static edu.harvard.hms.dbmi.avillach.auth.utils.AuthNaming.AuthRoleNaming.SUPER_ADMIN;

/**
 * <p>Endpoint for creating and updating terms of service entities. Records when a user accepts a term of service.</p>
 */
@Controller
@RequestMapping("/tos")
public class TermsOfSerivceController {

    private final TOSService tosService;

    @Autowired
    public TermsOfSerivceController(TOSService tosService) {
        this.tosService = tosService;
    }

    @ApiOperation(value = "GET the latest Terms of Service")
    @GetMapping(path = "/latest", produces = "text/html")
    public ResponseEntity<?> getLatestTermsOfService(){
        return PICSUREResponse.success(tosService.getLatest());
    }

    @ApiOperation(value = "Update the Terms of Service html body")
    @RolesAllowed({AuthNaming.AuthRoleNaming.ADMIN, SUPER_ADMIN})
    @PostMapping(path = "/update", consumes = "text/html", produces = "application/json")
    public ResponseEntity<?> updateTermsOfService(
            @ApiParam(required = true, value = "A html page for updating") String html){
        return PICSUREResponse.success(tosService.updateTermsOfService(html));
    }

    @ApiOperation(value = "GET if current user has acceptted his TOS or not")
    @GetMapping(path = "/", produces = "text/plain")
    public ResponseEntity<?> hasUserAcceptedTOS(){
        SecurityContext context = SecurityContextHolder.getContext();
        String userSubject = context.getAuthentication().getName();
        return PICSUREResponse.success(tosService.hasUserAcceptedLatest(userSubject));
    }

    @ApiOperation(value = "Endpoint for current user to accept his terms of service")
    @PostMapping(path = "/accept", produces = "application/json")
    public ResponseEntity<?> acceptTermsOfService(){
        SecurityContext context = SecurityContextHolder.getContext();
        String userSubject = context.getAuthentication().getName();
        tosService.acceptTermsOfService(userSubject);
        return PICSUREResponse.success();
    }

}
