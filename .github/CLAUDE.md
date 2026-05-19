# CLAUDE.md

## Workflow Orchestration

### 1. Plan Mode Default
- Enter plan mode for ANY non-trivial task (3+ steps)
- If something goes sideways, STOP and re-plan
- Never charge ahead without a written plan

### 2. Subagent Strategy
- Use subagents to keep main context clean
- One task per subagent for focused execution

### 3. Self-Improvement Loop
- After ANY correction: log to tasks/lessons.md
- Review lessons at session start

### 4. Verification Before Done
- Never mark complete without proving it works
- Run tests, check logs, demonstrate correctness

### 5. Demand Elegance (Balanced)
- If a fix feels hacky, implement the proper version
- Skip this for simple, obvious fixes

### 6. Autonomous Bug Fixing
- Bug report = just fix it, no hand-holding
- Point at logs, errors, failing tests, then resolve

### 7. Plan First
- Write the plan to tasks/todo.md with checkable items

### 8. Verify Plan, Track Progress
- Check in with me before starting; mark items as it goes

### 9. Explain Changes & Document Results
- High-level summary at every step; review section at end

### 10. Capture Lessons
- Update tasks/lessons.md after every correction

## Code Principles

### 11. Simplicity First
- Make every change as simple as possible

### 12. No Laziness
- Find root causes, no temporary fixes

### 13. Minimal Impact
- Touch only what's necessary, avoid new bugs

## Project Preferences

### 14. Separate Applications
- New capabilities should be delivered as separate applications
- Do NOT extend the existing repository unless explicitly told otherwise

### 15. API Integration Standards
- Follow existing patterns in the codebase for API calls
- Handle errors explicitly at system boundaries
- Never expose secrets in code or logs
