#Option one: direct link to JS event
<script type="text/javascript">
    document.getElementById("myButton").onclick = function () {
        location.href = ../README.md";
    };
</script>

```{r, echo=F}
actionButton("myButton", "Redirect")
```
