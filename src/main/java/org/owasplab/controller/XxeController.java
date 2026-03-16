package org.owasplab.controller;

import org.owasplab.service.XxeService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/xxe")
@CrossOrigin(origins = "*")
public class XxeController {

    private final XxeService xxeService;

    public XxeController(XxeService xxeService) {
        this.xxeService = xxeService;
    }

    @PostMapping("/parse-vuln")
    public Map<String, Object> parseVuln(@RequestBody Map<String, String> body) {
        String xml = body.getOrDefault("xml", "");
        return xxeService.parseVuln(xml);
    }

    @PostMapping("/parse-safe")
    public Map<String, Object> parseSafe(@RequestBody Map<String, String> body) {
        String xml = body.getOrDefault("xml", "");
        return xxeService.parseSafe(xml);
    }

    @GetMapping("/info")
    public Map<String, Object> info() {
        return xxeService.getInfo();
    }
}